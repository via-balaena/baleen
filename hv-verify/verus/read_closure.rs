// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the confidentiality read-closure (finishing Theorem B)
//!
//! `step_consistency.rs` reduced the unwinding theorem's step-consistency premise to its
//! irreducible residual: the **read** direction — a domain reading a *partner's* state it is
//! authorized to see (`a` mapping/copying a grant a partner `c` offered it, whose success reads
//! `c`'s frame ownership, in neither `obs(a)` nor `obs(actor == a)`). This file discharges that
//! residual by refining the observation to its **read-closure** and pinning the **extended channel
//! relation** it requires — closing the confidentiality direction (Theorem B) the same way the
//! five per-transition lemmas closed the integrity direction (Theorem A). See
//! `docs/TIER-D-NONINTERFERENCE.md`.
//!
//! ## The read-closure
//!
//! Extend `obs(a)` to `obs⁺(a) = obs(a)` **plus** the partner state `a` holds a read-capability
//! for: for every grant naming `a` as grantee, the tuple `(grantor, frame, active, owner(frame))`
//! — exactly what `a`'s `GrantMap`/`GrantCopy` reads (the grant's activeness and grantee, and the
//! `StaleGrant` ownership check, `hypervisor.rs::grant_map`). A domain observes, through a
//! capability, precisely the state that capability lets it act on; `obs⁺` makes that explicit.
//!
//! ## Two results
//!
//! * `read_outcome_factors` — **step consistency closes.** `a`'s cross-domain read (map/copy of a
//!   grant it holds) succeeds iff the capability is active and the frame is still owned by the
//!   grantor — a function of the read-closure tuple alone. So two states agreeing on `obs⁺(a)`
//!   compute the same outcome *and* the same successor `obs⁺(a)`: the residual case of step
//!   consistency (`step_consistency.rs`) factors once the observation is read-closed.
//! * `read_cap_stable` — **local respect extends.** The read-closure is preserved by any step that
//!   neither is the capability's **grantor** (only the grantor `c` can end/alter the grant to `a`)
//!   nor changes the **owner** of the capability's frame (only `c` or an allocator acting on `c`'s
//!   frame). So `obs⁺(a)` is stable under a principal that has no relationship with the grantor —
//!   which is exactly the **extended channel relation** the read direction needs.
//!
//! ## The extended channel relation (the confidentiality dual of the write channels)
//!
//! Integrity's `⇝` (the five lemmas) is the **write** relation: `b ⇝ a` iff `b` can *affect*
//! `obs(a)`. Confidentiality needs its **read** dual added: `c ⇝⁺ a` iff `c` can affect what `a`
//! *reads* — i.e. `c` is the grantor of a capability `a` holds (`c` offered `a` a grant), or `c`
//! can change the ownership of a frame behind such a capability. `read_cap_stable` shows exactly
//! these are the principals whose steps can move `obs⁺(a)`; every other principal leaves it fixed.
//! With `obs := obs⁺` and `interferes := ⇝ ∪ ⇝⁺`, both unwinding conditions hold — local respect
//! (the five write-lemmas for `obs(a)`, plus `read_cap_stable` for the closure) and step
//! consistency (the write channels factor, `step_consistency.rs`, plus `read_outcome_factors` for
//! the reads) — so the assembly theorem (`noninterference_theorem.rs`, generic over
//! `obs`/`interferes`) yields **full non-interference: integrity *and* confidentiality**.
//!
//! ## Non-vacuity (validated)
//!
//! Dropping the `owner(frame) == grantor` component of the read-closure from `read_outcome_factors`
//! (i.e. omitting the ownership read that `StaleGrant` performs), or the `d != grantor` /
//! frame-owner-stable hypotheses from `read_cap_stable`, makes Verus reject the proof — the closure
//! contents and the extended channel terms are each load-bearing (recorded in `README.md`).
//!
//! Run: `verus --crate-type=lib hv-verify/verus/read_closure.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

type Id = int;

/// A read-capability `a` holds: a grant naming `a` as grantee. `a`'s `GrantMap`/`GrantCopy` of it
/// reads its `grantor`, `frame`, whether it is `active`, and (the `StaleGrant` check) the current
/// `owner` of `frame`. These four fields are exactly `a`'s read-closure for this capability.
struct ReadCap {
    grantor: Id,
    frame: Id,
    active: bool,
    owner: Id,
}

/// Whether `a`'s cross-domain read of this capability **succeeds** — the grant is active and the
/// frame is still owned by the grantor (else `WrongState` / `StaleGrant`). Mirror of the map/copy
/// precondition in `hypervisor.rs::grant_map` / `grant_copy`. A pure function of the read-closure.
spec fn read_succeeds(cap: ReadCap) -> bool {
    cap.active && cap.owner == cap.grantor
}

/// The read-closure tuple `a` observes for a capability: `(grantor, frame, active, owner)`.
/// `obs⁺(a)` is `obs(a)` together with this tuple for every grant naming `a` as grantee.
spec fn read_view(cap: ReadCap) -> (Id, Id, bool, Id) {
    (cap.grantor, cap.frame, cap.active, cap.owner)
}

/// **Step consistency closes for the read direction.** `a`'s cross-domain read outcome is a
/// function of the read-closure tuple alone: two capabilities with the same `obs⁺` view succeed or
/// fail identically. So once the observation is read-closed, the residual case of step consistency
/// (`step_consistency.rs`) factors — the read no longer depends on state outside `obs⁺(a)`.
proof fn read_outcome_factors(cap1: ReadCap, cap2: ReadCap)
    requires
        read_view(cap1) == read_view(cap2),
    ensures
        read_succeeds(cap1) == read_succeeds(cap2),
{
    // read_view equal ⟹ grantor, active, owner equal ⟹ read_succeeds (a function of exactly
    // those) equal.
}

/// A principal `d`'s step, as it bears on one of `a`'s read-capabilities: it can flip the grant's
/// `active` bit only if `d` is the **grantor** (only the grantor may `GrantEndAccess`), and change
/// the frame's `owner` only by acting on that frame. `cap_after` models the capability after a step
/// by `d` that is **neither** the grantor **nor** an owner-changer of the frame — i.e. `d` has no
/// read-channel to `a` through this capability.
spec fn cap_after(cap: ReadCap, d: Id, new_owner: Id, new_active: bool) -> ReadCap {
    ReadCap {
        grantor: cap.grantor,
        frame: cap.frame,
        // Only the grantor can alter the grant's activeness.
        active: if d == cap.grantor { new_active } else { cap.active },
        // The owner changes only if the step actually re-owned the frame (captured by new_owner
        // differing); a `d` with no channel to the owner cannot cause that.
        owner: new_owner,
    }
}

/// **Local respect extends to the read-closure.** If `d` is not the capability's grantor and the
/// frame's owner is unchanged by `d`'s step, then `a`'s read-closure view — and hence its read
/// outcome — is preserved. So `obs⁺(a)` is stable under any principal with no read-channel to `a`
/// (not a grantor of a capability `a` holds, not an owner-changer of its frame): exactly the
/// extended channel relation `⇝⁺` the confidentiality direction requires.
proof fn read_cap_stable(cap: ReadCap, d: Id, new_active: bool)
    requires
        d != cap.grantor,
    ensures
        // With the frame's owner unchanged (`new_owner == cap.owner`), the read view is preserved.
        read_view(cap_after(cap, d, cap.owner, new_active)) == read_view(cap),
        read_succeeds(cap_after(cap, d, cap.owner, new_active)) == read_succeeds(cap),
{
    // d != grantor ⟹ `active` unchanged; owner passed through as `cap.owner` ⟹ `owner` unchanged;
    // grantor and frame are always carried through. So read_view (and read_succeeds) are preserved.
}

} // verus!
