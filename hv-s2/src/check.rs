// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The refinement properties, as executable predicates
//!
//! What [`crate::leaf_map`] *guarantees*, written as checkable functions rather than prose. These
//! are run over **every reachable state** by `hv-sim`'s enumerator and over fuzzed call sequences by
//! `hv-fuzz` — replacing the three hand-written mutations Architecture Audit #2 relied on — and they
//! are the predicates the follow-on arc lifts to ∀-N in Verus/Kani.
//!
//! ## Two kinds of property, and the honest difference
//!
//! **[`check_authorized`] is the isolation theorem.** It answers "may this domain reach this frame?"
//! through a route the emitter never touches: [`hv_core::p2m::System::owner_of`] plus the **grant
//! subsystem** ([`hv_core::grant::System::authorizes`]). The emitter walks `link_edges`; this walks
//! ownership and grants. Two independent derivations agreeing over every reachable state is
//! evidence; it also *composes* with hv-core's `UnauthorizedForeignLink` invariant, which is what
//! makes a foreign leaf imply a grant in the first place. It is now proven ∀-N — over an arbitrary
//! edge population in Verus, and on this shipped predicate by Kani over every ownership assignment
//! and grant table at bounded edge count (`docs/STAGE2-REFINEMENT-FORALL-N.md`).
//!
//! **The premise is now discharged too.** That theorem was stated conditional on
//! `UnauthorizedForeignLink`, which at the time was enumerator-checked with a Tier-B locality cutoff
//! but proven by no Verus file. (An earlier revision of this comment called it "already-proven"; it
//! was not, and the correction is the point of design-lesson #37.) Arc 3b
//! (`hv-verify/verus/foreign_link_preservation.rs`) proves its **preservation step ∀-N** for every
//! transition class that can move toward violating it, so the composition no longer rests on an
//! un-proven invariant. The residual is narrower and named in
//! `docs/STAGE2-REFINEMENT-FORALL-N.md` §7 — chiefly that the *completeness* of that transition
//! list is an audit argument backed by the enumerator, not a machine-checked fact.
//!
//! **[`check_exact`] is a consistency check, not a theorem.** It re-derives the expected map from
//! the same `link_edges` relation the emitter reads, so it cannot fail for a *reason the emitter got
//! the relation wrong* — it can only catch the emitter mis-applying it (a missed clear, a stale
//! leaf, a wrong permission, an ordering bug). That is worth checking, and the enumerator makes it
//! cheap, but calling it a proof of the refinement would be an overclaim. Named as such here so no
//! reader mistakes it for one.
//!
//! That distinction is the inverse of design-lesson #14c: production code wants **one** derivation
//! (so it cannot drift); a *checker* wants a **second, independent** one (so it cannot be a
//! tautology).

use hv_core::hypervisor::DomId;
use hv_core::p2m::Mfn;
use hv_core::Hypervisor;

use crate::arm64::TABLE_ENTRIES;
use crate::leafmap::{leaf_map, Perm};

/// A way the emitted Stage-2 leaf map can betray the model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Violation {
    /// **The isolation failure.** A frame is mapped that the domain neither owns nor holds an
    /// authorizing grant for — the hardware would let a guest reach memory the model forbids.
    UnauthorizedMapping {
        /// The domain whose table maps it.
        dom: DomId,
        /// The frame reached.
        mfn: Mfn,
        /// Who owns it (`None` = unallocated).
        owner: Option<DomId>,
        /// At what permission it was mapped.
        perm: Perm,
    },
    /// A foreign frame is mapped **writable** while the authorizing grant is read-only — a
    /// privilege escalation across the grant seam.
    WriteEscalation {
        /// The domain whose table maps it.
        dom: DomId,
        /// The frame reached.
        mfn: Mfn,
        /// The grantor whose read-only grant was escalated.
        owner: DomId,
    },
    /// The emitted map disagrees with the model's leaf-edge relation (see [`check_exact`]).
    Inexact {
        /// The domain whose map disagrees.
        dom: DomId,
        /// The frame at which they differ.
        mfn: Mfn,
        /// What the emitter produced.
        mapped: Option<Perm>,
        /// What the model's edges say.
        expected: Option<Perm>,
    },
    /// The model authorized a frame the table cannot represent.
    Overflow {
        /// The domain whose map overflowed.
        dom: DomId,
        /// The frame that did not fit.
        mfn: Mfn,
    },
}

/// **P-SOUND + P-PERM — no reachability without authorization.**
///
/// For every mapped frame: either the domain **owns** it, or an **active grant** from its owner
/// authorizes this domain at (at least) the mapped permission. Derived through `owner_of` + the
/// grant subsystem — *independently* of the `link_edges` walk the emitter uses.
pub fn check_authorized(
    hv: &Hypervisor,
    dom: DomId,
    leaves: &[Option<Perm>],
) -> Result<(), Violation> {
    check_authorized_with(
        dom,
        leaves,
        |m| hv.p2m().owner_of(m),
        |grantor, grantee, frame, writable| {
            hv.grant().authorizes(grantor, grantee, frame, writable)
        },
    )
}

/// [`check_authorized`], with the two model reads it makes lifted into parameters: frame
/// ownership and the grant *permit* relation.
///
/// The same #14c seam as [`crate::leafmap::leaf_map_from_edges`], for the same reason —
/// `hv-verify`'s Kani harnesses cannot build a whole [`Hypervisor`] symbolically, but they *can*
/// drive this function against a symbolic ownership assignment and a symbolic grant table, which
/// makes the proof one about the shipped predicate rather than a re-modelled copy.
/// [`check_authorized`] is the two-line wrapper production uses.
pub fn check_authorized_with<O, A>(
    dom: DomId,
    leaves: &[Option<Perm>],
    owner_of: O,
    authorizes: A,
) -> Result<(), Violation>
where
    O: Fn(Mfn) -> Option<DomId>,
    A: Fn(DomId, DomId, Mfn, bool) -> bool,
{
    for (m, leaf) in leaves.iter().enumerate() {
        let Some(perm) = *leaf else { continue };
        let mfn = m as Mfn;
        let owner = owner_of(mfn);
        // Its own frame: ownership is the authorization.
        if owner == Some(dom) {
            continue;
        }
        // Unallocated frames are owned by nobody and can authorize nothing.
        let Some(grantor) = owner else {
            return Err(Violation::UnauthorizedMapping {
                dom,
                mfn,
                owner,
                perm,
            });
        };
        let writable = perm == Perm::Rw;
        if !authorizes(grantor, dom, mfn, writable) {
            // Distinguish "no grant at all" from "a read-only grant mapped writable" — the second
            // is the sharper diagnosis, and the mutation class Audit #2 called RW-for-an-RO-leaf.
            return Err(if writable && authorizes(grantor, dom, mfn, false) {
                Violation::WriteEscalation {
                    dom,
                    mfn,
                    owner: grantor,
                }
            } else {
                Violation::UnauthorizedMapping {
                    dom,
                    mfn,
                    owner,
                    perm,
                }
            });
        }
    }
    Ok(())
}

/// **P-EXACT — the map equals the model's leaf-edge relation.**
///
/// A *consistency* check (see the module docs): it re-derives from the same `link_edges` relation
/// the emitter reads, so it catches mis-application — a missed clear, a surviving stale leaf, a
/// wrong permission, an ordering bug — but not a misunderstanding of the relation itself.
pub fn check_exact(hv: &Hypervisor, dom: DomId, leaves: &[Option<Perm>]) -> Result<(), Violation> {
    let edges = hv.p2m().link_edges();
    for (m, mapped) in leaves.iter().enumerate() {
        let mfn = m as Mfn;
        // The model's verdict for this frame: the LAST leaf edge into it from a table `dom` owns
        // (later edges overwrite earlier ones, exactly as the emitter applies them).
        let mut expected: Option<Perm> = None;
        for (parent, _slot, child, writable, leaf) in edges.iter().copied() {
            if leaf && child == mfn && hv.p2m().owner_of(parent) == Some(dom) {
                expected = Some(if writable { Perm::Rw } else { Perm::Ro });
            }
        }
        if *mapped != expected {
            return Err(Violation::Inexact {
                dom,
                mfn,
                mapped: *mapped,
                expected,
            });
        }
    }
    Ok(())
}

/// Emit every domain's leaf map from the live model and check every property against it.
///
/// This is the whole-state predicate the enumerator and the fuzzer call. Dead domains are included
/// deliberately: a Dead slot owns nothing and holds nothing, so its map must be empty — the
/// emitter's view of the lifecycle's "a Dead domain is a clean shell".
/// Called once per transition by the enumerator (millions of times in a deep sweep), so it is
/// sized to the model's **actual** frame count rather than the full [`TABLE_ENTRIES`] table: the
/// work is then `O(domains × (frames × edges))` over the tiny configs the enumerator uses, instead
/// of a 512-slot sweep per call. Frames beyond the model's count cannot be mapped — the model has
/// no such frame to link — so the prefix is the whole truth.
pub fn check_all(hv: &Hypervisor) -> Result<(), Violation> {
    let frames = hv.p2m().frame_count().min(TABLE_ENTRIES);
    let mut buf = [None; TABLE_ENTRIES];
    let leaves = &mut buf[..frames];
    for dom in 0..hv.domain_count() {
        let dom = dom as DomId;
        if let Err(e) = leaf_map(hv.p2m(), dom, leaves) {
            return Err(Violation::Overflow { dom, mfn: e.mfn });
        }
        check_authorized(hv, dom, leaves)?;
        check_exact(hv, dom, leaves)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hv_core::p2m::PtLevel;
    use hv_core::HvCall;

    const DOM0: DomId = 0;
    const DOM1: DomId = 1;
    const CAP: usize = 8;

    fn hv() -> Hypervisor {
        Hypervisor::new(4, 4, 4, 2, 2, CAP)
    }
    fn ok(h: &mut Hypervisor, dom: DomId, call: HvCall) {
        assert!(h.dispatch(dom, call).is_ok(), "setup call failed: {call:?}");
    }
    fn rooted(h: &mut Hypervisor, dom: DomId, root: Mfn) {
        ok(h, dom, HvCall::P2mAllocate { mfn: root });
        ok(
            h,
            dom,
            HvCall::P2mPin {
                mfn: root,
                level: PtLevel::L1,
            },
        );
    }

    /// A fresh model, and one with a domain's own frames, both satisfy every property.
    #[test]
    fn honest_states_pass() {
        let mut h = hv();
        assert_eq!(check_all(&h), Ok(()), "a fresh model must be clean");
        rooted(&mut h, DOM0, 1);
        ok(&mut h, DOM0, HvCall::P2mAllocate { mfn: 2 });
        ok(
            &mut h,
            DOM0,
            HvCall::P2mLink {
                parent: 1,
                slot: 0,
                child: 2,
                writable: true,
                leaf: true,
            },
        );
        assert_eq!(
            check_all(&h),
            Ok(()),
            "own frames are authorized by ownership"
        );
    }

    /// A Dead domain reaches nothing.
    #[test]
    fn dead_domain_maps_nothing() {
        let h = hv();
        let mut leaves = [None; TABLE_ENTRIES];
        assert!(leaf_map(h.p2m(), DOM1, &mut leaves).is_ok());
        assert!(leaves.iter().all(|l| l.is_none()));
        assert_eq!(check_all(&h), Ok(()));
    }

    /// NON-VACUITY: a hand-forged map that reaches a peer's frame with no grant is CAUGHT. This is
    /// the mutation class "map the ungranted frame" — the isolation failure the whole build exists
    /// to prevent — asserted here against the checker rather than by perturbing the emitter.
    #[test]
    fn unauthorized_mapping_is_caught() {
        let mut h = hv();
        ok(
            &mut h,
            DOM0,
            HvCall::DomainCreate {
                target: DOM1,
                may_create: false,
            },
        );
        rooted(&mut h, DOM1, 3);
        ok(&mut h, DOM1, HvCall::P2mAllocate { mfn: 4 });
        ok(
            &mut h,
            DOM1,
            HvCall::P2mLink {
                parent: 3,
                slot: 0,
                child: 4,
                writable: true,
                leaf: true,
            },
        );
        // Forge dom0's map so it reaches dom1's frame 4, which dom1 never granted.
        let mut forged = [None; TABLE_ENTRIES];
        forged[4] = Some(Perm::Rw);
        assert_eq!(
            check_authorized(&h, DOM0, &forged),
            Err(Violation::UnauthorizedMapping {
                dom: DOM0,
                mfn: 4,
                owner: Some(DOM1),
                perm: Perm::Rw,
            })
        );
    }

    /// NON-VACUITY: mapping an *unallocated* frame is caught — nobody owns it, so nothing can
    /// authorize it.
    #[test]
    fn mapping_an_unowned_frame_is_caught() {
        let h = hv();
        let mut forged = [None; TABLE_ENTRIES];
        forged[6] = Some(Perm::Ro);
        assert_eq!(
            check_authorized(&h, DOM0, &forged),
            Err(Violation::UnauthorizedMapping {
                dom: DOM0,
                mfn: 6,
                owner: None,
                perm: Perm::Ro,
            })
        );
    }

    /// A *granted* foreign frame IS authorized — the checker must not over-restrict, or it would
    /// reject the legitimate cross-domain sharing the model permits.
    #[test]
    fn granted_foreign_frame_is_authorized() {
        let mut h = hv();
        ok(
            &mut h,
            DOM0,
            HvCall::DomainCreate {
                target: DOM1,
                may_create: false,
            },
        );
        ok(&mut h, DOM1, HvCall::P2mAllocate { mfn: 4 });
        // dom1 grants dom0 read/write access to frame 4.
        ok(
            &mut h,
            DOM1,
            HvCall::GrantAccess {
                gref: 0,
                grantee: DOM0,
                frame: 4,
                readonly: false,
            },
        );
        let mut mapped = [None; TABLE_ENTRIES];
        mapped[4] = Some(Perm::Rw);
        assert_eq!(
            check_authorized(&h, DOM0, &mapped),
            Ok(()),
            "a granted foreign frame must be accepted"
        );
    }

    /// NON-VACUITY: a READ-ONLY grant mapped WRITABLE is caught as an escalation — the mutation
    /// class Audit #2 called "RW for an RO leaf", now diagnosed through the grant subsystem.
    #[test]
    fn write_escalation_over_a_readonly_grant_is_caught() {
        let mut h = hv();
        ok(
            &mut h,
            DOM0,
            HvCall::DomainCreate {
                target: DOM1,
                may_create: false,
            },
        );
        ok(&mut h, DOM1, HvCall::P2mAllocate { mfn: 4 });
        // dom1 grants dom0 READ-ONLY access to frame 4.
        ok(
            &mut h,
            DOM1,
            HvCall::GrantAccess {
                gref: 0,
                grantee: DOM0,
                frame: 4,
                readonly: true,
            },
        );
        // Read-only mapping: fine.
        let mut ro = [None; TABLE_ENTRIES];
        ro[4] = Some(Perm::Ro);
        assert_eq!(check_authorized(&h, DOM0, &ro), Ok(()));
        // Writable mapping over the same read-only grant: an escalation.
        let mut rw = [None; TABLE_ENTRIES];
        rw[4] = Some(Perm::Rw);
        assert_eq!(
            check_authorized(&h, DOM0, &rw),
            Err(Violation::WriteEscalation {
                dom: DOM0,
                mfn: 4,
                owner: DOM1,
            })
        );
    }

    /// NON-VACUITY: a map that disagrees with the model's edges is caught — the "stale leaf" and
    /// "over-restriction" mutation classes.
    #[test]
    fn inexact_map_is_caught() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        ok(&mut h, DOM0, HvCall::P2mAllocate { mfn: 2 });
        ok(
            &mut h,
            DOM0,
            HvCall::P2mLink {
                parent: 1,
                slot: 0,
                child: 2,
                writable: true,
                leaf: true,
            },
        );

        // A stale leaf: frame 3 mapped though no edge reaches it.
        let mut stale = [None; TABLE_ENTRIES];
        stale[2] = Some(Perm::Rw);
        stale[3] = Some(Perm::Rw);
        assert!(matches!(
            check_exact(&h, DOM0, &stale),
            Err(Violation::Inexact { mfn: 3, .. })
        ));

        // Over-restriction: an authorized leaf dropped.
        let empty = [None; TABLE_ENTRIES];
        assert!(matches!(
            check_exact(&h, DOM0, &empty),
            Err(Violation::Inexact {
                mfn: 2,
                mapped: None,
                expected: Some(Perm::Rw),
                ..
            })
        ));
    }
}
