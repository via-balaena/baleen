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

use hv_core::p2m::{DomId, Mfn, PageType, PtLevel, System};

/// A live page-table edge, exactly as [`System::link_edges`] yields it:
/// `(parent, slot, child, writable, leaf)`.
///
/// Named so the proof harnesses can build one symbolically without re-modelling the tuple
/// (design-lesson #14c: one derivation, consumed by production and proof alike).
pub type Edge = (Mfn, u32, Mfn, bool, bool);

/// The permission a Stage-2 leaf carries. The model's `writable` bit, named at the layer that
/// consumes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    /// Read-only — a guest *write* to this frame must take a permission fault.
    Ro,
    /// Read/write.
    Rw,
}

/// How much guest memory ONE emitted leaf covers.
///
/// **The architecture-neutral name for what the model expresses as a page-table LEVEL — and the
/// reason a raw level must never cross this seam.** `hv_core::PtLevel` counts *up* from the bottom
/// (`L1`'s entries map ordinary pages) while ARM counts *down* from the root (`L3`'s entries map
/// 4 KiB pages). The two conventions are **order-reversing**, so a `level: u8` passed across this
/// boundary would be an inversion waiting to happen the first time a third level is added. A span
/// says what is actually meant and is true on every architecture; turning a span into a descriptor
/// level is [`crate::arm64`]'s job alone, and the byte sizes live there too (this layer must stay
/// neutral enough to serve x86 EPT).
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Span {
    /// One base page — the smallest mapping the architecture supports (4 KiB on both targets).
    Base,
    /// One level up: a whole base-level table's worth of contiguous memory in a single leaf
    /// (2 MiB on both targets). The model has had these since design-lesson #14; the metal
    /// flattened them to [`Span::Base`] until this arc.
    Super,
}

/// The two per-span leaf maps a domain's Stage-2 emission is built from.
///
/// **Why two flat maps and not one map of `(Perm, Span)`.** Keeping a separate `Mfn`-indexed array
/// per span preserves the property the whole ∀-N proof rests on: each map is a *total function over
/// its index space*, so two leaves in the same map cannot overlap — it is not representable. Mixing
/// spans into one index space would make overlap representable and therefore something that has to
/// be *proven* rather than something the shape forbids. Across the two maps, non-overlap is
/// likewise structural: [`crate::arm64`] gives each span its own disjoint IPA window.
pub struct Maps<'a> {
    /// Leaves covering one base page, indexed by [`Mfn`].
    pub base: &'a mut [Option<Perm>],
    /// Leaves covering one super page, indexed by [`Mfn`].
    pub sup: &'a mut [Option<Perm>],
}

/// Why a leaf map could not be emitted. Every variant is a **loud** failure: the pre-Arc-1 emitter
/// dropped such cases with a bare `continue`, which fails *open*.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    /// An authorized frame does not fit the map capacity for its span.
    OutOfRange(FrameOutOfRange),
    /// One frame is a leaf under tables at **two different spans**, so it would need two distinct
    /// machine-frame backings — which the `Mfn` → host-PA function cannot represent (each span has
    /// its own window, so the same `Mfn` in both maps would name two different physical addresses,
    /// breaking the one-`Mfn`-is-one-machine-frame refinement).
    ///
    /// **The model permits this and nothing in `hv-core` forbids it**: `MislevelledLink` constrains
    /// an *interior* entry's child against the parent's level, but a *leaf's* child is
    /// `Writable`-or-untyped at any level, so a frame really can be a leaf under an `L1` and an
    /// `L2` table at once. Surfaced by unfolding the statement for this arc (#37), and rejected
    /// here rather than silently canonicalised to one span.
    SpanConflict {
        /// The frame claimed at two spans.
        mfn: Mfn,
    },
    /// A leaf edge hangs off a table whose level this refinement does not emit (e.g. a model `L3`
    /// leaf — a 1 GiB block). Rejected rather than approximated: treating it as a [`Span::Super`]
    /// would emit a mapping that is simply the wrong size.
    UnsupportedSpan {
        /// The parent table whose level is out of range.
        parent: Mfn,
    },
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
pub fn leaf_map(p2m: &System, dom: DomId, out: Maps<'_>) -> Result<(), MapError> {
    leaf_map_from_edges(
        &p2m.link_edges(),
        |m| p2m.owner_of(m),
        |parent| span_of_table(p2m, parent),
        dom,
        out,
    )
}

/// The span a leaf edge out of table `parent` covers — the ONE place the model's level convention is
/// translated into this layer's neutral one (see [`Span`] on why the level itself must not cross).
///
/// `hv_core::PtLevel::L1` is the *bottom* level, so its leaves are base pages; `L2` is one up, so
/// its leaves are super pages. Anything higher is [`MapError::UnsupportedSpan`].
pub fn span_of_table(p2m: &System, parent: Mfn) -> Option<Span> {
    match p2m.current_type(parent) {
        Some(PageType::PageTable(PtLevel::L1)) => Some(Span::Base),
        Some(PageType::PageTable(PtLevel::L2)) => Some(Span::Super),
        _ => None,
    }
}

/// [`leaf_map`], with the model reads it makes lifted into parameters: the live edge set and
/// the frame-ownership function.
///
/// **This is the function the refinement theorem is about.** [`leaf_map`] is a two-line wrapper
/// that supplies `p2m.link_edges()` and `p2m.owner_of` — so the emitter has exactly one
/// derivation (design-lesson #14c) while the decision itself becomes reachable to a prover that
/// cannot construct a whole `System` symbolically. `hv-verify`'s Kani harnesses drive *this*
/// function over arbitrary edge sets, ownership assignments and capacities; the Verus mirror
/// lifts the same loop to an arbitrary edge *count*. Neither proves a re-modelled copy.
///
/// The loop's guarantee, stated as the proof uses it:
///
/// > every `out[m] == Some(π)` is **witnessed** by an edge in `edges` with `leaf == true`,
/// > `owner_of(parent) == Some(dom)`, `child == m`, and `π = writable ? Rw : Ro`.
///
/// That witness plus hv-core's `UnauthorizedForeignLink` is the whole authorization argument —
/// see [`crate::check::check_authorized`].
pub fn leaf_map_from_edges<O, S>(
    edges: &[Edge],
    owner_of: O,
    span_of: S,
    dom: DomId,
    out: Maps<'_>,
) -> Result<(), MapError>
where
    O: Fn(Mfn) -> Option<DomId>,
    S: Fn(Mfn) -> Option<Span>,
{
    let Maps { base, sup } = out;
    // Clear the FULL capacity of BOTH maps first — the no-stale-leaf property (module docs). Doing
    // it per-map keeps totality per index space, which is what makes intra-map overlap
    // unrepresentable rather than merely absent.
    for slot in base.iter_mut() {
        *slot = None;
    }
    for slot in sup.iter_mut() {
        *slot = None;
    }
    for (parent, _slot, child, writable, leaf) in edges.iter().copied() {
        // Only leaves map a frame; only tables this domain owns are its reachability.
        if !leaf || owner_of(parent) != Some(dom) {
            continue;
        }
        // The span is a property of the PARENT's level, not of the child — a frame does not know
        // how much of the address space maps it.
        let span = span_of(parent).ok_or(MapError::UnsupportedSpan { parent })?;
        let target: &mut [Option<Perm>] = match span {
            Span::Base => base,
            Span::Super => sup,
        };
        let idx = child as usize;
        if idx >= target.len() {
            return Err(MapError::OutOfRange(FrameOutOfRange {
                mfn: child,
                capacity: target.len(),
            }));
        }
        target[idx] = Some(if writable { Perm::Rw } else { Perm::Ro });
    }
    // One frame must have exactly ONE span, or it would need two machine-frame backings (see
    // `MapError::SpanConflict`). Checked as a total post-pass rather than inline, so the result does
    // not depend on the order edges happen to arrive in.
    let shared = base.len().min(sup.len());
    for mfn in 0..shared {
        if base[mfn].is_some() && sup[mfn].is_some() {
            return Err(MapError::SpanConflict { mfn: mfn as Mfn });
        }
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
        assert!(leaf_map(
            hv.p2m(),
            DOM0,
            Maps {
                base: &mut out,
                sup: &mut []
            }
        )
        .is_ok());
        assert!(out.iter().all(|s| s.is_none()), "a hole-only map: {out:?}");
    }

    #[test]
    fn own_writable_leaf_maps_rw_and_nothing_else() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 2, 0, true);

        let mut out = [None; CAP];
        assert!(leaf_map(
            h.p2m(),
            DOM0,
            Maps {
                base: &mut out,
                sup: &mut []
            }
        )
        .is_ok());
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
        assert!(leaf_map(
            h.p2m(),
            DOM0,
            Maps {
                base: &mut out,
                sup: &mut []
            }
        )
        .is_ok());
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
            assert!(leaf_map(
                h.p2m(),
                DOM0,
                Maps {
                    base: &mut out,
                    sup: &mut []
                }
            )
            .is_ok());
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
        assert!(leaf_map(
            h.p2m(),
            DOM0,
            Maps {
                base: &mut a,
                sup: &mut []
            }
        )
        .is_ok());
        assert_eq!(a[2], Some(Perm::Rw), "dom0 sees its own frame");
        assert_eq!(a[4], None, "dom0 must NOT see dom1's frame");

        let mut b = [None; CAP];
        assert!(leaf_map(
            h.p2m(),
            DOM1,
            Maps {
                base: &mut b,
                sup: &mut []
            }
        )
        .is_ok());
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
        assert!(leaf_map(
            h.p2m(),
            DOM0,
            Maps {
                base: &mut out,
                sup: &mut []
            }
        )
        .is_ok());
        assert_eq!(out[2], Some(Perm::Rw));
        // Same buffer, different domain: dom0's leaf must be GONE, not merely joined by dom1's.
        assert!(leaf_map(
            h.p2m(),
            DOM1,
            Maps {
                base: &mut out,
                sup: &mut []
            }
        )
        .is_ok());
        assert_eq!(out[2], None, "stale leaf survived a rebuild");
        assert_eq!(out[4], Some(Perm::Rw));
    }

    /// Pin `root` at `level` and link `child` under it as a leaf — the span comes from the PARENT's
    /// level, so this is how a SUPER leaf is built (level `L2`) versus a base one (`L1`).
    fn leaf_at(
        hv: &mut Hypervisor,
        dom: DomId,
        root: Mfn,
        level: PtLevel,
        child: Mfn,
        slot: u32,
        writable: bool,
    ) {
        ok(hv, dom, HvCall::P2mAllocate { mfn: root });
        ok(hv, dom, HvCall::P2mPin { mfn: root, level });
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

    /// A leaf under an `L2` table is a SUPER span and lands in the super map, not the base one —
    /// the whole point of the arc. Before this, the model's superpage (design-lesson #14) was
    /// flattened into a base-page descriptor.
    #[test]
    fn l2_leaf_is_a_super_span() {
        let mut h = hv();
        leaf_at(&mut h, DOM0, 1, PtLevel::L2, 2, 0, true);

        let mut base = [None; CAP];
        let mut sup = [None; CAP];
        assert!(leaf_map(
            h.p2m(),
            DOM0,
            Maps {
                base: &mut base,
                sup: &mut sup
            }
        )
        .is_ok());
        assert_eq!(
            sup[2],
            Some(Perm::Rw),
            "the L2 leaf belongs to the super map"
        );
        assert_eq!(base[2], None, "and must NOT also appear as a base page");
    }

    /// A base leaf still lands in the base map — the existing behaviour, pinned so the span
    /// dimension cannot silently promote everything.
    #[test]
    fn l1_leaf_is_a_base_span() {
        let mut h = hv();
        leaf_at(&mut h, DOM0, 1, PtLevel::L1, 2, 0, false);

        let mut base = [None; CAP];
        let mut sup = [None; CAP];
        assert!(leaf_map(
            h.p2m(),
            DOM0,
            Maps {
                base: &mut base,
                sup: &mut sup
            }
        )
        .is_ok());
        assert_eq!(base[2], Some(Perm::Ro));
        assert_eq!(sup[2], None);
    }

    /// **The hazard the model does not forbid.** One frame as a leaf under BOTH an `L1` and an `L2`
    /// table would need two machine-frame backings (each span has its own window), which the
    /// `Mfn` → host-PA function cannot represent. `hv-core` permits it — `MislevelledLink`
    /// constrains only *interior* children — so the refinement must reject it loudly.
    #[test]
    fn one_frame_at_two_spans_is_rejected() {
        let mut h = hv();
        leaf_at(&mut h, DOM0, 1, PtLevel::L1, 3, 0, true);
        // A second, L2-level table of the same domain, leafing at the SAME child frame.
        ok(&mut h, DOM0, HvCall::P2mAllocate { mfn: 2 });
        ok(
            &mut h,
            DOM0,
            HvCall::P2mPin {
                mfn: 2,
                level: PtLevel::L2,
            },
        );
        ok(
            &mut h,
            DOM0,
            HvCall::P2mLink {
                parent: 2,
                slot: 0,
                child: 3,
                writable: true,
                leaf: true,
            },
        );

        let mut base = [None; CAP];
        let mut sup = [None; CAP];
        assert_eq!(
            leaf_map(
                h.p2m(),
                DOM0,
                Maps {
                    base: &mut base,
                    sup: &mut sup
                }
            ),
            Err(MapError::SpanConflict { mfn: 3 })
        );
    }

    /// An authorized frame that does not fit is an ERROR, never a silent omission.
    #[test]
    fn frame_beyond_capacity_is_an_error() {
        let mut h = hv();
        rooted(&mut h, DOM0, 1);
        own_leaf(&mut h, DOM0, 1, 5, 0, true);

        let mut small = [None; 3]; // capacity 3 cannot hold frame 5
        assert_eq!(
            leaf_map(
                h.p2m(),
                DOM0,
                Maps {
                    base: &mut small,
                    sup: &mut []
                }
            ),
            Err(MapError::OutOfRange(FrameOutOfRange {
                mfn: 5,
                capacity: 3
            }))
        );
    }
}
