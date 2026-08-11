// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! The **one-way observation channel** — a safety monitor that cannot be blinded by the
//! partition it watches.
//!
//! ## Why this exists
//!
//! `docs/CONSUMER-CORTENFORGE.md` derives a mixed-criticality role: an untrusted learned
//! control policy in one partition, a safety monitor in another. The monitor must *observe*
//! the policy or it is not a monitor — and the metal's thesis boot asserts that **no channel**
//! exists between its two guests, which is the precondition of the Tier-D non-interference
//! theorem (`docs/TIER-D-NONINTERFERENCE.md` §2.2).
//!
//! ⚠ **Tier D is not weakened by this.** Local respect is a conditional —
//! `¬(b ⇝ a) ⟹ obs(a)` unchanged — and `⇝` already includes **consent (grant)** as one of its
//! five authorized channels. An authorized grant enters a branch the theorem already covers.
//! What changes is the *deployment's* `no_channel` claim, which is why this is a **separate
//! boot configuration** and the thesis boot is untouched.
//!
//! ## The finding this module exists to witness
//!
//! The obvious design — the policy owns its telemetry frame and offers the monitor a
//! **read-only** grant — is **wrong, and wrong in a way that is invisible until you ask who
//! holds the capability** (design-lesson #271, the ㉕ shape).
//!
//! `grant::end_access` refuses with `InUse` **only while a mapping is held**, and a
//! `GrantCopy` deliberately takes no reference (`grant::copy` is `&self` and "changes no
//! state"). So nothing holds the grant open, and **the untrusted policy can revoke it and
//! blind its own safety monitor**. Consent is the right model for cooperative tenants and the
//! wrong one for an adversarial tenant.
//!
//! **Phase A witnesses exactly that failure**, because a kill probe that cannot demonstrate
//! the flaw is decorative.
//!
//! ## The repair — invert ownership
//!
//! **Phase B**: the *monitor* owns the telemetry frame and offers the *policy* writable
//! access. The policy maps it and writes; the monitor reads its own memory with **no
//! hypercall at all**. The monitor's read capability is then unrevocable, because access to
//! one's own page is not something another domain can withdraw.
//!
//! ★★ **The witness is in the TYPE, and that is the strongest thing here.**
//! `HvCall::GrantEndAccess { gref: GrantRef }` **has no grantor field**. A domain can only ever
//! name a slot in *its own* grant table, so "the policy revokes the monitor's grant" is not a
//! call that gets *refused* — it is a call that **cannot be written**. Grant refs and map
//! handles are per-domain namespaces throughout (`grant.rs`'s
//! `a_handle_names_only_the_callers_own_maptrack`: *"cross-domain handle confusion is
//! unrepresentable, which is stronger than catching it"*).
//!
//! Phase B's runtime check — the policy naming [`GREF_B`] and reaching its own slot, which was
//! never populated — is therefore a *demonstration* of a property the API surface already
//! guarantees, not the guarantee itself. ⚠ Stated that way round deliberately: a test that
//! passes because a slot happens to be empty is a weaker thing than what is actually true here,
//! and conflating them is how a rung becomes decorative. See [`GREF_B`] for why the two phases
//! must not share a slot — the first draft of this module had them sharing one, and phase B was
//! quietly passing on phase A's side effect.
//!
//! ⚠ **The trade, taken deliberately: the policy can now CORRUPT the shared page.** Accepted —
//! the contents are the untrusted partition's own claims about itself and were never
//! trustworthy, so the monitor must validate them regardless. A *blinded* monitor is a safety
//! failure; a *lying* one was always the assumption. **Trust the channel's existence, never
//! its contents.**
//!
//! ⚠ **Residual, undischarged and stated:** the policy can simply stop writing. That is
//! **denial, not deception**, and it is detectable by a freshness field the monitor reads —
//! which this module does not build, because staleness detection is a property of the
//! telemetry format rather than of the channel.
//!
//! ⚠ **Scope.** This runs against the proven model on the metal; it witnesses what the *model*
//! permits and refuses. It is not a statement about a real device, and no real telemetry
//! crosses it.

use core::fmt::Write;

use hv_core::grant::{Frame, GrantRef};
use hv_core::hypervisor::{DomId, HvCall, HvOutcome, Hypervisor};

use crate::pl011::Pl011;

/// The control domain that creates the other two. Boots `Live` with `may_create`.
const DOM0: DomId = 0;
/// The **safety monitor** — trusted, and in phase B the owner of the telemetry frame.
const MONITOR_DOM: DomId = 1;
/// The **untrusted control policy** — the partition whose behaviour is a consequence of
/// training rather than of proof.
const POLICY_DOM: DomId = 2;

/// The frame the *policy* owns in phase A (the naive, revocable direction).
const F_POLICY_OWNED: Frame = 1;
/// The frame the *monitor* owns in phase B (the inverted, unrevocable direction).
const F_MONITOR_OWNED: Frame = 2;

/// Phase A's grant slot, in the **policy's** table.
const GREF_A: GrantRef = 0;

/// Phase B's grant slot. ⚠ **Deliberately a DIFFERENT number from [`GREF_A`], and the reason is
/// the whole soundness of phase B's check.**
///
/// The two phases must not share a slot. Phase A ends the policy's grant at [`GREF_A`], so after
/// it runs the policy's slot 0 is `Free` — and a phase-B check that the policy "cannot end
/// `GREF_A`" would then be passing on **phase A's leftover side effect**, not on the namespace
/// property it claims. Worse, it would inverting-ly *depend on the flaw*: if phase A ever stopped
/// being able to revoke, slot 0 would still be occupied and phase B would fail for a reason
/// unrelated to what it tests.
///
/// Using an untouched slot makes "the policy's own table holds nothing here" true **by
/// construction**, and keeps the two phases independent. The monitor grants at *its own*
/// `GREF_B`; that the two domains name the same number is exactly the point.
const GREF_B: GrantRef = 1;

/// Dispatch one call and return the model's verdict, without halting. Phases here *expect*
/// refusals, so unlike `guest::expect` a failure is data rather than a bug.
fn call(hv: &mut Hypervisor, caller: DomId, c: HvCall) -> bool {
    crate::teardown::dispatch(hv, caller, c).is_ok()
}

/// Bring both partitions to life. Neither gets the creation capability.
fn create_partitions(hv: &mut Hypervisor) -> bool {
    [MONITOR_DOM, POLICY_DOM].into_iter().all(|target| {
        call(
            hv,
            DOM0,
            HvCall::DomainCreate {
                target,
                may_create: false,
            },
        )
    })
}

/// **Phase A — the naive direction, which must FAIL to hold.**
///
/// The policy owns the telemetry frame and offers the monitor a read-only grant. The monitor
/// observes through `GrantCopy`, which takes no reference — so nothing holds the grant open,
/// and the policy can end it. Returns `true` when the blinding was *successfully
/// demonstrated*, which is the outcome this phase wants.
fn phase_a_consent_is_revocable(hv: &mut Hypervisor, uart: &mut Pl011) -> bool {
    if !call(
        hv,
        POLICY_DOM,
        HvCall::P2mAllocate {
            mfn: F_POLICY_OWNED,
        },
    ) {
        let _ = writeln!(uart, "baleen: observe FAIL — phase A could not allocate");
        return false;
    }
    // The policy offers the monitor a READ-ONLY view of its own frame.
    if !call(
        hv,
        POLICY_DOM,
        HvCall::GrantAccess {
            gref: GREF_A,
            grantee: MONITOR_DOM,
            frame: F_POLICY_OWNED,
            readonly: true,
        },
    ) {
        let _ = writeln!(uart, "baleen: observe FAIL — phase A grant refused");
        return false;
    }

    // The monitor can observe: a grant-checked copy, no reference taken.
    let observed_before = call(
        hv,
        MONITOR_DOM,
        HvCall::GrantCopy {
            grantor: POLICY_DOM,
            gref: GREF_A,
            write: false,
        },
    );

    // ⚠ THE DEFECT: nothing holds the grant open, so the observed party revokes it.
    let revoked = call(hv, POLICY_DOM, HvCall::GrantEndAccess { gref: GREF_A });

    // The monitor is now blind.
    let observed_after = call(
        hv,
        MONITOR_DOM,
        HvCall::GrantCopy {
            grantor: POLICY_DOM,
            gref: GREF_A,
            write: false,
        },
    );

    let blinded = observed_before && revoked && !observed_after;
    if blinded {
        let _ = writeln!(
            uart,
            "baleen: observe A: the policy revoked its own grant and BLINDED the monitor \
             (consent is revocable; a copy holds nothing open)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: observe FAIL — phase A did not demonstrate blinding \
             (before={observed_before} revoked={revoked} after={observed_after}); \
             the probe proves nothing if it cannot kill"
        );
    }
    blinded
}

/// **Phase B — the inverted direction, which must HOLD.**
///
/// The monitor owns the frame and offers the policy writable access. The policy maps it and
/// writes; the monitor reads its own memory and issues no call at all. Returns `true` when the
/// policy has been shown to have no reach into the monitor's read capability.
fn phase_b_ownership_is_not_revocable(hv: &mut Hypervisor, uart: &mut Pl011) -> bool {
    if !call(
        hv,
        MONITOR_DOM,
        HvCall::P2mAllocate {
            mfn: F_MONITOR_OWNED,
        },
    ) {
        let _ = writeln!(uart, "baleen: observe FAIL — phase B could not allocate");
        return false;
    }
    // The MONITOR is the grantor now: it offers the policy a writable telemetry window.
    if !call(
        hv,
        MONITOR_DOM,
        HvCall::GrantAccess {
            gref: GREF_B,
            grantee: POLICY_DOM,
            frame: F_MONITOR_OWNED,
            readonly: false,
        },
    ) {
        let _ = writeln!(uart, "baleen: observe FAIL — phase B grant refused");
        return false;
    }
    // The policy takes the mapping it writes telemetry through.
    let mapped = matches!(
        crate::teardown::dispatch(
            hv,
            POLICY_DOM,
            HvCall::GrantMap {
                grantor: MONITOR_DOM,
                gref: GREF_B,
                writable: true,
            },
        ),
        Ok(HvOutcome::Handle(_))
    );

    // ★ THE WITNESS, and it is a NAMESPACE fact rather than a permission check: the policy names
    //   `GREF_B` and reaches its OWN grant table, whose slot `GREF_B` was never populated by
    //   anything (see the const's doc — sharing a slot with phase A made this pass on phase A's
    //   side effect instead). There is no call by which it can name the MONITOR's slot at all:
    //   `HvCall::GrantEndAccess { gref }` carries no grantor field.
    let policy_cannot_reach = !call(hv, POLICY_DOM, HvCall::GrantEndAccess { gref: GREF_B });

    // ★ AND the monitor cannot yank it mid-flight either: `InUse` refuses an end while the
    //   mapping is live. The channel is stable in BOTH directions once established.
    let stable_while_mapped = !call(hv, MONITOR_DOM, HvCall::GrantEndAccess { gref: GREF_B });

    let held = mapped && policy_cannot_reach && stable_while_mapped;
    if held {
        let _ = writeln!(
            uart,
            "baleen: observe B: the policy cannot reach the monitor's grant (its own gref \
             namespace holds nothing); the monitor reads its own frame with no hypercall, so \
             the read capability is unrevocable"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: observe FAIL — phase B did not hold (mapped={mapped} \
             policy_cannot_reach={policy_cannot_reach} stable={stable_while_mapped})"
        );
    }
    held
}

/// Run both phases against a freshly built model and report. Non-terminal: this configuration
/// returns and the boot continues, unlike the W^X probes whose faults are terminal.
pub(crate) fn run(uart: &mut Pl011) {
    let mut hv = crate::build_hypervisor();

    if !create_partitions(&mut hv) {
        let _ = writeln!(
            uart,
            "baleen: observe FAIL — could not create the monitor/policy partitions"
        );
        return;
    }

    let a = phase_a_consent_is_revocable(&mut hv, uart);
    let b = phase_b_ownership_is_not_revocable(&mut hv, uart);

    if a && b {
        let _ = writeln!(
            uart,
            "baleen: observe: one-way channel established — consent is revocable by the \
             observed party, ownership is not; the monitor owns the page"
        );
    }
}
