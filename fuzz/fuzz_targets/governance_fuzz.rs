#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use multisig_governance::{
    GovernanceContract, GovernanceContractClient, ProposalStatus, MAX_SIGNERS,
    MIN_TIMELOCK_SECONDS, PROPOSAL_TTL_SECONDS,
};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal, Symbol, Val, Vec as SorobanVec};

// ─── Mock target contract ─────────────────────────────────────────────────────
// Minimal contract that accepts `set_admin` calls so that
// `finalize_admin_transfer`'s cross-contract invocation succeeds.
// Real target-contract integration testing is out of scope.

#[contract]
pub struct MockTarget;

#[contractimpl]
impl MockTarget {
    pub fn set_admin(_env: Env, _new_admin: Address) {
        // no-op
    }
}

// ─── Fuzz input types ─────────────────────────────────────────────────────────

/// Size of the pre-generated address pool that signers are drawn from.
const SIGNER_POOL_SIZE: usize = 8;

/// Cap on the action sequence length to keep each iteration fast.
const MAX_ACTIONS: usize = 32;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    actions: Vec<GovAction>,
}

#[derive(Arbitrary, Debug)]
enum GovAction {
    /// Propose a new admin transfer with arbitrary parameters.
    Propose {
        /// Number of signers (bounded to [1, SIGNER_POOL_SIZE]).
        num_signers: u8,
        /// Threshold for approval quorum.
        threshold: u8,
        /// Extra seconds above MIN_TIMELOCK_SECONDS for the delay.
        delay_extra: u32,
        /// If true, duplicate the first signer to test rejection.
        inject_duplicate: bool,
    },
    /// Approve the pending proposal with a signer from the pool.
    Approve { signer_idx: u8 },
    /// Approve twice with the same signer to test idempotency.
    DuplicateApprove { signer_idx: u8 },
    /// Attempt to finalize the pending proposal.
    Finalize,
    /// Cancel the pending proposal (admin-only).
    Cancel,
    /// Emergency-cancel with an arbitrary proposal ID.
    EmergencyCancel { proposal_id: u8 },
    /// Expire the pending proposal (anyone, if TTL elapsed).
    Expire,
    /// Advance ledger time by a given number of seconds.
    AdvanceTime { seconds: u32 },
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Resilient contract call — wraps `try_invoke_contract` so panics inside the
/// contract are returned as `Err` rather than aborting the fuzzer.
macro_rules! rcall {
    ($env:expr, $client:expr, $func:expr, ($($arg:expr),*)) => {
        $env.try_invoke_contract::<Val, Val>(
            &$client.address,
            &Symbol::new($env, $func),
            ($($arg.clone(),)*).into_val($env),
        )
    };
}

// ─── Fuzz target ──────────────────────────────────────────────────────────────

fuzz_target!(|input: FuzzInput| {
    let env = Env::default();
    env.mock_all_auths();

    // ── Setup ────────────────────────────────────────────────────────────────

    // Register the mock target so finalize's cross-contract call succeeds.
    let target_id = env.register(MockTarget, ());

    // Register and initialize the governance contract.
    let gov_id = env.register(GovernanceContract, ());
    let client = GovernanceContractClient::new(&env, &gov_id);

    let admin = Address::generate(&env);
    client.initialize(&admin, &target_id);

    // Pre-generate a fixed pool of signer addresses.
    let signer_pool: Vec<Address> = (0..SIGNER_POOL_SIZE)
        .map(|_| Address::generate(&env))
        .collect();

    // Shadow state — tracks what the admin *should* be so we can detect
    // unexpected mutations at every step.
    let mut expected_admin = admin.clone();
    let mut current_time: u64 = env.ledger().timestamp();

    // ── Execute action sequence ──────────────────────────────────────────────

    let actions = if input.actions.len() > MAX_ACTIONS {
        &input.actions[..MAX_ACTIONS]
    } else {
        &input.actions
    };

    for action in actions {
        // Snapshot admin before every action.
        let admin_before = client.get_current_admin();

        match action {
            // ── Propose ──────────────────────────────────────────────────
            GovAction::Propose {
                num_signers,
                threshold,
                delay_extra,
                inject_duplicate,
            } => {
                // Bound signer count to [1, SIGNER_POOL_SIZE].
                let n = ((*num_signers as u32) % (MAX_SIGNERS)).max(1) as usize;
                let n = n.min(SIGNER_POOL_SIZE);

                // FIXED: Replaced range loops with .iter().take(n) to satisfy clippy
                let mut signers = SorobanVec::new(&env);
                for s in signer_pool.iter().take(n) {
                    signers.push_back(s.clone());
                }

                // Optionally inject a duplicate to exercise rejection.
                if *inject_duplicate && n > 0 {
                    signers.push_back(signer_pool[0].clone());
                }

                let thresh = (*threshold as u32).max(1);
                let delay: u64 = MIN_TIMELOCK_SECONDS + (*delay_extra as u64);
                let proposed_new_admin = Address::generate(&env);

                let result = rcall!(
                    &env,
                    client,
                    "propose_admin_transfer",
                    (proposed_new_admin, signers, thresh, delay)
                );

                // INV: Proposals with duplicate signers MUST be rejected.
                if *inject_duplicate && result.is_ok() {
                    panic!("Proposal with duplicate signers was accepted — (4020) guard failed");
                }

                // INV: Propose never changes the admin.
                assert_eq!(
                    client.get_current_admin(),
                    admin_before,
                    "Admin must not change from propose"
                );
            }

            // ── Approve ──────────────────────────────────────────────────
            GovAction::Approve { signer_idx } => {
                let idx = (*signer_idx as usize) % SIGNER_POOL_SIZE;
                let signer = signer_pool[idx].clone();

                // Snapshot approval count before.
                let count_before = client.get_pending().map(|p| p.approvals.len()).unwrap_or(0);

                let result = rcall!(&env, client, "approve_transfer", (signer));

                if result.is_ok() {
                    let count_after = client.get_approval_count();

                    // Approval count must increase by at most 1.
                    assert!(
                        count_after >= count_before && count_after <= count_before + 1,
                        "Approval count changed unexpectedly: {} -> {}",
                        count_before,
                        count_after
                    );
                }

                // INV: Approve never changes the admin.
                assert_eq!(
                    client.get_current_admin(),
                    admin_before,
                    "Admin must not change from approve"
                );
            }

            // ── DuplicateApprove (INV-2) ─────────────────────────────────
            GovAction::DuplicateApprove { signer_idx } => {
                let idx = (*signer_idx as usize) % SIGNER_POOL_SIZE;
                let signer = signer_pool[idx].clone();

                // First approval.
                let first = rcall!(&env, client, "approve_transfer", (signer));

                if first.is_ok() {
                    let count_after_first = client.get_approval_count();

                    // Second approval with the SAME signer.
                    let _ = rcall!(&env, client, "approve_transfer", (signer));

                    let count_after_second = client.get_approval_count();

                    // INV-2: No duplicate-signer threshold bypass.
                    assert_eq!(
                        count_after_first, count_after_second,
                        "Duplicate approval must not inflate count: {} vs {}",
                        count_after_first, count_after_second
                    );
                }

                // INV: Approve never changes the admin.
                assert_eq!(
                    client.get_current_admin(),
                    admin_before,
                    "Admin must not change from duplicate approve"
                );
            }

            // ── Finalize (INV-1, INV-3) ──────────────────────────────────
            GovAction::Finalize => {
                let caller = Address::generate(&env);

                // Capture proposal state BEFORE finalize — it's deleted on
                // success so we can't inspect it afterwards.
                let pending_snapshot = client.get_pending();

                let result = rcall!(&env, client, "finalize_admin_transfer", (caller));

                if result.is_ok() {
                    // ── Finalize SUCCEEDED — verify all preconditions ─────
                    if let Some(p) = pending_snapshot {
                        // INV-1a: Proposal was active.
                        assert_eq!(
                            p.status,
                            ProposalStatus::Active,
                            "Finalized proposal must have been Active"
                        );

                        // INV-1b: Threshold was met.
                        assert!(
                            p.approvals.len() >= p.threshold,
                            "Finalize requires threshold: approvals={} threshold={}",
                            p.approvals.len(),
                            p.threshold
                        );

                        // INV-1c: Timelock had elapsed.
                        assert!(
                            current_time >= p.executable_after,
                            "Finalize requires timelock elapsed: now={} executable_after={}",
                            current_time,
                            p.executable_after
                        );

                        // INV-1d: Proposal had not expired (TTL).
                        let expiry = p.proposed_at.saturating_add(PROPOSAL_TTL_SECONDS);
                        assert!(
                            current_time < expiry,
                            "Finalize must occur before TTL: now={} expiry={}",
                            current_time,
                            expiry
                        );

                        // INV-3: Admin is now the proposed admin.
                        let new_admin = client.get_current_admin();
                        assert_eq!(
                            new_admin, p.proposed_admin,
                            "Admin must equal proposed_admin after finalize"
                        );
                        expected_admin = p.proposed_admin.clone();
                    } else {
                        panic!("Finalize succeeded with no pending proposal");
                    }

                    // No active proposal should remain after finalize.
                    assert!(
                        !client.has_pending_transfer(),
                        "No active proposal after successful finalize"
                    );
                } else {
                    // ── Finalize FAILED — admin must be unchanged ─────────
                    assert_eq!(
                        client.get_current_admin(),
                        admin_before,
                        "Admin must not change on failed finalize"
                    );
                }
            }

            // ── Cancel ───────────────────────────────────────────────────
            GovAction::Cancel => {
                let result = rcall!(&env, client, "cancel_admin_transfer", ());

                if result.is_ok() {
                    // Proposal must no longer be active.
                    assert!(
                        !client.has_pending_transfer(),
                        "No active proposal after cancel"
                    );
                }

                // INV: Cancel never changes the admin.
                assert_eq!(
                    client.get_current_admin(),
                    admin_before,
                    "Admin must not change from cancel"
                );
            }

            // ── Emergency Cancel ─────────────────────────────────────────
            GovAction::EmergencyCancel { proposal_id } => {
                let pid = *proposal_id as u32;
                let none_reason = Option::<soroban_sdk::String>::None;

                let result = rcall!(
                    &env,
                    client,
                    "emergency_cancel_proposal",
                    (pid, none_reason)
                );

                if result.is_ok() {
                    assert!(
                        !client.has_pending_transfer(),
                        "No active proposal after emergency cancel"
                    );
                }

                // INV: Emergency cancel never changes the admin.
                assert_eq!(
                    client.get_current_admin(),
                    admin_before,
                    "Admin must not change from emergency cancel"
                );
            }

            // ── Expire ───────────────────────────────────────────────────
            GovAction::Expire => {
                let caller = Address::generate(&env);

                // Snapshot the proposal before expire removes it.
                let pending_snapshot = client.get_pending();

                let result = rcall!(&env, client, "expire_proposal", (caller));

                if result.is_ok() {
                    // Pending proposal must be removed.
                    assert!(
                        client.get_pending().is_none(),
                        "Pending must be removed after expire"
                    );

                    // Verify proposal was genuinely past TTL.
                    if let Some(p) = &pending_snapshot {
                        let expiry = p.proposed_at.saturating_add(PROPOSAL_TTL_SECONDS);
                        assert!(
                            current_time >= expiry,
                            "Expire must only succeed after TTL: now={} expiry={}",
                            current_time,
                            expiry
                        );
                    }
                }

                // INV: Expire never changes the admin.
                assert_eq!(
                    client.get_current_admin(),
                    admin_before,
                    "Admin must not change from expire"
                );
            }

            // ── AdvanceTime ──────────────────────────────────────────────
            GovAction::AdvanceTime { seconds } => {
                // Bound to 2× TTL to keep values realistic while still
                // allowing exploration past expiry boundaries.
                let advance = (*seconds as u64) % (PROPOSAL_TTL_SECONDS * 2);
                current_time = current_time.saturating_add(advance);

                env.ledger().with_mut(|li| {
                    li.timestamp = current_time;
                });
            }
        }

        // ── Global invariant: admin always matches expected value ─────────
        assert_eq!(
            client.get_current_admin(),
            expected_admin,
            "Admin diverged from expected value"
        );
    }
});
