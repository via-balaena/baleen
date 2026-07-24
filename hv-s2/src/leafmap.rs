// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The architecture-neutral refinement — `p2m` → a Stage-2 leaf map
//!
//! This module is the isolation content of Stage-2 emission, and *only* that: which machine frames
//! a domain's page table reaches, at what permission. No descriptor bits, no addresses, no
//! architecture — so the property proven here holds equally for AArch64 Stage-2 ([`crate::arm64`])
//! and, later, x86 EPT.
//!
//! ## The relation
//!
//! [`leaf_map`] computes, for domain `G`, the total function
//!
//! > `leaf(G, m) = Some(π)` **⟺** `m` is a **leaf** child of a page table `G` **owns**, at
//! > permission `π` (`writable → Rw`, else `Ro`); `None` otherwise (a translation-fault hole).
//!
//! That biconditional is the refinement `docs/AUDIT-2-P2M-STAGE2.md` argues in prose. Extracting it
//! here makes it a property of a pure function — checkable over every reachable state by
//! `hv-sim`'s enumerator, and provable ∀-N in the follow-on arc.
//!
//! ## Why *ownership of the parent* is the whole authorization story
//!
//! The filter is `owner_of(parent) == Some(G)` — deliberately **not** a grant lookup. A *foreign*
//! child (one `G` does not own) can only be a child of `G`'s table because [`hv_core`]'s
//! `p2m_link` seam already required a matching grant, and the standing `UnauthorizedForeignLink`
//! invariant keeps it so for every edge at every level. So the grant dimension is covered
//! **transitively, by an invariant already proven**, and this function stays a pure structural
//! read. Re-checking grants here would duplicate a proven check and risk drift (design-lesson
//! #14c); *verifying* the composition is the enumerator's job, not the emitter's.
//!
//! ## Totality — why every slot is written
//!
//! The map is cleared over its **full capacity** before any leaf is placed, not over a live frame
//! count. That is load-bearing for the rebuild cases: a reborn tenant (M5 Arc 0) or a peer domain
//! sharing a table set (M5 Arc 2) must not inherit a stale leaf from the previous occupant. Keying
//! the clear on capacity makes "no stale leaf" structural rather than a property of how many frames
//! happen to be allocated.

use hv_core::p2m::{DomId, Mfn, System};

/// The permission a Stage-2 leaf carries. The model's `writable` bit, named at the layer that
/// consumes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    /// Read-only — a guest *write* to this frame must take a permission fault.
    Ro,
    /// Read/write.
    Rw,
}

/// A frame the model says the domain may reach falls outside the caller's map capacity.
///
/// Returned rather than silently skipped. The previous in-metal emitter dropped such a frame with a
/// bare `continue`, which is a **silent under-map** — unreachable while the model stays far below
/// the table capacity, but a hole that would fail *open* into "the guest cannot see memory it is
/// entitled to" rather than failing loudly. Making it an error lets the metal halt with a
/// diagnosable message instead (the fail-loud discipline the device arcs adopted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameOutOfRange {
    /// The frame the model authorized.
    pub mfn: Mfn,
    /// The capacity of the map it did not fit in.
    pub capacity: usize,
}

/// Emit `dom`'s Stage-2 leaf map into `out`, indexed by [`Mfn`].
///
/// `out.len()` is the frame capacity; **every** slot is written (see the module docs on totality),
/// so a reused buffer never retains a previous domain's leaf. Returns [`FrameOutOfRange`] if an
/// authorized frame does not fit — never a silent omission.
pub fn leaf_map(p2m: &System, dom: DomId, out: &mut [Option<Perm>]) -> Result<(), FrameOutOfRange> {
    // Clear the FULL capacity first — the no-stale-leaf property (module docs).
    for slot in out.iter_mut() {
        *slot = None;
    }
    for (parent, _slot, child, writable, leaf) in p2m.link_edges() {
        // Only leaves map a frame; only tables this domain owns are its reachability.
        if !leaf || p2m.owner_of(parent) != Some(dom) {
            continue;
        }
        let idx = child as usize;
        if idx >= out.len() {
            return Err(FrameOutOfRange {
                mfn: child,
                capacity: out.len(),
            });
        }
        out[idx] = Some(if writable { Perm::Rw } else { Perm::Ro });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hv_core::p2m::PtLevel;
    use hv_core::{HvCall, Hypervisor};

    const DOM0: DomId = 0;
    const DOM1: DomId = 1;
    const CAP: usize = 8;

    /// A hypervisor sized like the metal's bring-up config.
    fn hv() -> Hypervisor {
        Hypervisor::new(4, 4, 4, 2, 2, CAP)
    }

    fn ok(hv: &mut Hypervisor, dom: DomId, call: HvCall) {
        assert!(hv.dispatch(dom, call).is_ok(), "setup call failed");
    }

    /// Give `dom` a pinned L1 root and link `child` under it at `slot` as a leaf.
    fn own_leaf(hv: &mut Hypervisor, dom: DomId, root: Mfn, child: Mfn, slot: u32, writable: bool) {
        ok(hv, dom, HvCall::P2mAllocate { mfn: child });
        ok(
            hv,
            dom,
            HvCall::P2mLink {
                parent: root,
                slot,
                child,
                writable,
                leaf: true,
            },
        );
    }

    fn rooted(hv: &mut Hypervisor, dom: DomId, root: Mfn) {
        ok(hv, dom, HvCall::P2mAllocate { mfn: root });
        ok(
            hv,
            dom,
            HvCall::P2mPin {
                mfn: root,
                level: PtLevel::L1,
            },
        );
    }

    #[test]
    fn empty_p2m_maps_nothing() {
        let hv = hv();
        let mut out = [Some(Perm::Rw); CAP]; // pre-dirtied: the clear must overwrite it
        assert!(leaf_map(hv.p2m(), DOM0, &mut out).is_ok());
        assert!(out.iter().all(|s| s.is_none()), "a hole-only map: {out:?}");
    }

    #[test]
    fn own_writable_leaf_maps_rw_and_nothing_else() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 2, 0, true);

        let mut out = [None; CAP];
        assert!(leaf_map(h.p2m(), DOM0, &mut out).is_ok());
        assert_eq!(out[2], Some(Perm::Rw), "the linked leaf is mapped RW");
        for (m, slot) in out.iter().enumerate() {
            if m != 2 {
                assert_eq!(*slot, None, "frame {m} must be a hole");
            }
        }
    }

    #[test]
    fn read_only_leaf_maps_ro() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 2, 0, false);

        let mut out = [None; CAP];
        assert!(leaf_map(h.p2m(), DOM0, &mut out).is_ok());
        assert_eq!(out[2], Some(Perm::Ro), "a non-writable leaf is RO, not RW");
    }

    /// The parent table itself is reachable as *structure*, never as a data leaf — an interior edge
    /// maps nothing. (write-xor-pagetable, seen from the emitter's side.)
    #[test]
    fn interior_edge_maps_nothing() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        ok(&mut h, DOM0, HvCall::P2mAllocate { mfn: 2 });
        ok(
            &mut h,
            DOM0,
            HvCall::P2mPin {
                mfn: 2,
                level: PtLevel::L1,
            },
        );
        // An interior (leaf = false) edge: 1 -> 2 as a sub-table, not a data page.
        let linked = h.dispatch(
            DOM0,
            HvCall::P2mLink {
                parent: 1,
                slot: 0,
                child: 2,
                writable: false,
                leaf: false,
            },
        );
        if linked.is_ok() {
            let mut out = [None; CAP];
            assert!(leaf_map(h.p2m(), DOM0, &mut out).is_ok());
            assert!(
                out.iter().all(|s| s.is_none()),
                "an interior edge must map no frame: {out:?}"
            );
        }
    }

    /// A peer's leaf is not in this domain's map — the `owner_of(parent)` filter IS the isolation.
    #[test]
    fn peer_leaves_are_not_mapped() {
        let mut h = hv();
        ok(
            &mut h,
            DOM0,
            HvCall::DomainCreate {
                target: DOM1,
                may_create: false,
            },
        );
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 2, 0, true);
        rooted(&mut h, DOM1, 3);
        own_leaf(&mut h, DOM1, 3, 4, 0, true);

        let mut a = [None; CAP];
        assert!(leaf_map(h.p2m(), DOM0, &mut a).is_ok());
        assert_eq!(a[2], Some(Perm::Rw), "dom0 sees its own frame");
        assert_eq!(a[4], None, "dom0 must NOT see dom1's frame");

        let mut b = [None; CAP];
        assert!(leaf_map(h.p2m(), DOM1, &mut b).is_ok());
        assert_eq!(b[4], Some(Perm::Rw), "dom1 sees its own frame");
        assert_eq!(b[2], None, "dom1 must NOT see dom0's frame");
    }

    /// Re-emitting into a REUSED buffer leaves no trace of the previous domain — the no-stale-leaf
    /// property the reborn-tenant (Arc 0) and two-domain (Arc 2) cases rely on.
    #[test]
    fn rebuild_clears_stale_leaves() {
        let mut h = hv();
        ok(
            &mut h,
            DOM0,
            HvCall::DomainCreate {
                target: DOM1,
                may_create: false,
            },
        );
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 2, 0, true);
        rooted(&mut h, DOM1, 3);
        own_leaf(&mut h, DOM1, 3, 4, 0, true);

        let mut out = [None; CAP];
        assert!(leaf_map(h.p2m(), DOM0, &mut out).is_ok());
        assert_eq!(out[2], Some(Perm::Rw));
        // Same buffer, different domain: dom0's leaf must be GONE, not merely joined by dom1's.
        assert!(leaf_map(h.p2m(), DOM1, &mut out).is_ok());
        assert_eq!(out[2], None, "stale leaf survived a rebuild");
        assert_eq!(out[4], Some(Perm::Rw));
    }

    /// An authorized frame that does not fit is an ERROR, never a silent omission.
    #[test]
    fn frame_beyond_capacity_is_an_error() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 5, 0, true);

        let mut small = [None; 3]; // capacity 3 cannot hold frame 5
        assert_eq!(
            leaf_map(h.p2m(), DOM0, &mut small),
            Err(FrameOutOfRange {
                mfn: 5,
                capacity: 3
            })
        );
    }
}
