// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # hv-verify — Tier C deductive-verification harnesses
//!
//! Tier A closed the *bounded* gaps and Tier B ([`docs/TIER-B-CUTOFF.md`]) proved the depth
//! axis for every bounded-state config via saturation — then handed three obligations to
//! Tier C that **enumeration provably cannot reach**, because they quantify over *all*
//! states rather than enumerate small ones. The cleanest of the three is the **refcount
//! infinity**: `grant::map` bumps `maps: u32` with no cap, so the reachable set is genuinely
//! infinite along the counter axis and no model checker can close it. Tier B *argued* the
//! refcount invariants are inductive inequalities "insensitive to magnitude" (§1.4); this
//! crate begins discharging that argument as a **machine-checked theorem**.
//!
//! ## The bridge: Kani first, Verus next
//!
//! [Kani](https://github.com/model-checking/kani) symbolically executes **real** hv-core
//! code, so a scalar made `kani::any::<u32>()` is proven over *all* 2³² values via its SMT
//! backend — with no loop unwinding, because a counter is not a collection. That is exactly
//! the unbounded counter dimension Tier B could not enumerate. The harnesses below prove the
//! **preservation step** — `∀ pre-state satisfying INV, one transition ⇒ INV still holds` —
//! for the grant refcount invariant `WritableExceedsMaps`, over every refcount magnitude.
//!
//! Faithfulness is the whole point of a verification project, so the proofs call the *same*
//! [`hv_core::grant::System::counts_after_map`] / [`counts_after_unmap`] the production
//! [`map`]/[`unmap`] transitions call (design-lesson #14c — one derivation, no drift), not a
//! re-modelled copy. Proving these is proving a property of the shipped code.
//!
//! **What this bridge does NOT cover — and where the ∀-N step now lives:** the counter is
//! unbounded here, but the *table size* (number of grant entries / live mappings) is not — the
//! relational invariant `RefcountMismatch` (`maps == |live mappings|`) couples a scalar to a
//! `Vec` length, which Kani would have to `unwind`. Arbitrary table size at once is the ∀-N job
//! of the **Verus** phase, which now discharges it: `RefcountMismatch` is proven preserved by
//! grant `map` and `unmap` over an arbitrary entry table × arbitrary-length mapping sequence in
//! `hv-verify/verus/refcount_mismatch.rs` (a Verus-dialect mirror, verified out-of-band — see
//! `hv-verify/verus/README.md`). That closes, for all sizes, the two `kani::assume`s the unmap
//! harness below could only assert. The one companion harness that drives the
//! real [`System`] state machine end-to-end
//! (`grant_state_machine::real_map_preserves_first_violation_bounded`) is therefore
//! explicitly *bounded* on table size — it demonstrates the bridge reaches the full code, not
//! that size is closed. (That harness and the proof modules are `#[cfg(kani)]`-gated, so they
//! are absent from this rustdoc build and referred to by name, not linked.)
//!
//! [`counts_after_unmap`]: hv_core::grant::System::counts_after_unmap
//! [`map`]: hv_core::grant::System::map
//! [`unmap`]: hv_core::grant::System::unmap
//! [`System`]: hv_core::grant::System
//! [`docs/TIER-B-CUTOFF.md`]: https://github.com/via-balaena/baleen/blob/main/docs/TIER-B-CUTOFF.md

// Under a normal build there is nothing here: every harness is `#[cfg(kani)]`. The crate
// exists to be run with `cargo kani -p hv-verify`.

/// Unbounded-magnitude preservation proofs for the grant refcount invariant
/// `WritableExceedsMaps` (`writable_maps <= maps`) — the residual Tier B §1.4 flagged.
///
/// Each harness makes the refcounts fully symbolic and assumes only the invariant on the
/// *pre*-transition state, so a green result is a proof for **all** 2³² magnitudes at once —
/// the step enumeration cannot take.
#[cfg(kani)]
mod grant_refcount {
    use hv_core::grant::{GrantError, System};

    /// `WritableExceedsMaps` is preserved by the **map** count-transition, for every
    /// refcount magnitude. Because Kani's default checks include arithmetic overflow, a
    /// green run *also* proves the unchecked `writable_maps + 1` inside `counts_after_map`
    /// can never overflow given the invariant precondition — the exact safety Tier B §1.4
    /// asserted informally.
    #[kani::proof]
    fn writable_exceeds_maps_preserved_under_map() {
        let maps: u32 = kani::any();
        let writable_maps: u32 = kani::any();
        let writable: bool = kani::any();
        // The invariant on the pre-state: `writable_maps <= maps`.
        kani::assume(writable_maps <= maps);

        match System::counts_after_map(maps, writable_maps, writable) {
            // A successful map must leave the invariant standing…
            Ok((m, w)) => assert!(w <= m, "WritableExceedsMaps must survive a map"),
            // …and a refused (would-overflow) map is a no-op, so nothing to preserve.
            Err(GrantError::Overflow) => {}
            Err(_) => unreachable!("counts_after_map only rejects Overflow"),
        }
    }

    /// `WritableExceedsMaps` is preserved by the **unmap** count-transition — and *surfacing
    /// what that preservation depends on is itself a result of this spike.* The invariant is
    /// **not** self-inductive under unmap: with `writable = false`, `maps = 5`,
    /// `writable_maps = 5` it holds before yet fails after (`maps` drops to 4, `writable_maps`
    /// stays 5). Kani found exactly that counterexample when this harness assumed only
    /// `writable_maps <= maps`.
    ///
    /// The missing hypotheses are consequences of `RefcountMismatch` (`maps == |live maps|`,
    /// `writable_maps == |writable live maps|`) applied to the actual mapping being released:
    /// a live mapping is being removed (`maps >= 1`), and a **read-only** unmap removes one of
    /// the `maps` that is *not* among the `writable_maps`, so strictly fewer than `maps`
    /// mappings are writable (`writable_maps <= maps - 1`). Under those reachable-state facts
    /// the invariant survives for every magnitude.
    ///
    /// The honest reading, and the design lesson: the "±1 lockstep" Tier B §1.4 described is a
    /// **coupling** — `WritableExceedsMaps`'s inductiveness *borrows* from `RefcountMismatch`.
    /// You cannot prove the scalar inequality preserved in isolation; the relational invariant
    /// carries it. `RefcountMismatch`'s own preservation couples a scalar to a `Vec` length
    /// and is the Verus obligation that closes this loop.
    #[kani::proof]
    fn writable_exceeds_maps_preserved_under_unmap() {
        let maps: u32 = kani::any();
        let writable_maps: u32 = kani::any();
        let writable: bool = kani::any();

        // WritableExceedsMaps on the pre-state.
        kani::assume(writable_maps <= maps);
        // A live mapping is being removed (RefcountMismatch counts it in `maps`).
        kani::assume(maps >= 1);
        if !writable {
            // A read-only mapping is one of the `maps` but not one of the `writable_maps`,
            // so strictly fewer than `maps` mappings are writable.
            kani::assume(writable_maps <= maps - 1);
        }

        let (m, w) = System::counts_after_unmap(maps, writable_maps, writable);
        assert!(
            w <= m,
            "WritableExceedsMaps must survive an unmap of a live mapping"
        );
    }

    /// The ±1 lockstep is *exact*: mapping then unmapping a mapping of the same writability
    /// restores the counts precisely, at every magnitude — no drift, no leak. This is the
    /// scalar heart of the `RefcountMismatch` inductive equality (its `Vec`-length half is
    /// the Verus phase).
    #[kani::proof]
    fn map_then_unmap_restores_counts() {
        let maps: u32 = kani::any();
        let writable_maps: u32 = kani::any();
        let writable: bool = kani::any();
        kani::assume(writable_maps <= maps);

        if let Ok((m, w)) = System::counts_after_map(maps, writable_maps, writable) {
            let (m2, w2) = System::counts_after_unmap(m, w, writable);
            assert_eq!(
                (m2, w2),
                (maps, writable_maps),
                "map then unmap must not drift the refcounts"
            );
        }
    }
}

/// A companion **bounded** proof that the bridge reaches the real [`System`] state machine,
/// not only the extracted arithmetic. Bounded on table size (Kani unwinds `first_violation`'s
/// loops); the *unbounded counter* guarantee is the scalar proofs in `grant_refcount`, and
/// arbitrary table size at once is the Verus phase.
///
/// [`System`]: hv_core::grant::System
#[cfg(kani)]
mod grant_state_machine {
    use hv_core::grant::System;

    /// Build a real 2-domain / 2-grant `System`, offer a grant over a symbolic frame with
    /// symbolic read-only-ness, drive a symbolic map, and assert the real `first_violation()`
    /// finds nothing — the actual invariant, on the actual transition, over the symbolic
    /// inputs. A refused map (writable vs read-only) is a legitimate no-op; either way no
    /// invariant may break.
    #[kani::proof]
    #[kani::unwind(5)]
    fn real_map_preserves_first_violation_bounded() {
        let mut s = System::new(2, 2);
        let frame: u32 = kani::any();
        let readonly: bool = kani::any();
        s.grant_access(0, 0, 1, frame, readonly).unwrap();

        let writable: bool = kani::any();
        let _ = s.map(1, 0, 0, writable);

        assert!(
            s.first_violation().is_none(),
            "a real grant map must leave no grant-table invariant violated"
        );
    }
}

/// # The Stage-2 **encoding**, proven bit-precisely (the refinement's third arrow)
///
/// The chain the metal's isolation rests on is
///
/// ```text
///     p2m model  ->  leaf map  ->  descriptor words  ->  hardware
/// ```
///
/// `hv-sim`'s enumerator checks the first arrow over every reachable state, and `hv_s2::check`
/// states the property. The **third** arrow — the leaf map expressed as the `u64`s the MMU walks —
/// was covered only by golden unit tests over a handful of example addresses. It is pure bit
/// manipulation over a scalar, which is exactly what Kani closes: a `kani::any::<u64>()` output
/// address is proven over *all* 2⁶⁴ values via the SMT backend, with no loop unwinding, because a
/// descriptor is not a collection.
///
/// These harnesses call the **same** [`hv_s2::arm64`] encoders/decoders the metal uses (no
/// re-modelled copy — design-lesson #14c), so proving them is proving a property of the shipped
/// emitter.
#[cfg(kani)]
mod stage2_encoding {
    use hv_s2::arm64::{decode_block, decode_page, decode_table, desc, Decoded};
    use hv_s2::Perm;

    /// A data leaf round-trips: for **every** output address and **both** permissions, encoding a
    /// 4 KiB page then decoding it recovers exactly the address, the permission, and execute-never.
    #[kani::proof]
    fn page_encoding_round_trips() {
        let pa: u64 = kani::any();
        let writable: bool = kani::any();
        let (perm, attrs) = if writable {
            (Perm::Rw, desc::PAGE_RW)
        } else {
            (Perm::Ro, desc::PAGE_RO)
        };
        let d = (pa & desc::ADDR_4K) | attrs;
        assert!(
            decode_page(d)
                == Some(Decoded {
                    pa: pa & desc::ADDR_4K,
                    perm,
                    xn: true,
                }),
            "a page descriptor must decode to exactly what it was encoded from"
        );
    }

    /// **The shared-image invariant, over every possible image address.** The guest-image block is
    /// the one mapping two domains hold in common (M5 Arc 2 identity-maps the same host frames into
    /// both), so it must be read-only — never a cross-domain *write* channel — and executable, since
    /// the guest fetches its code from it. Until this arc that rested on a comment.
    #[kani::proof]
    fn image_block_is_always_readonly_and_executable() {
        let pa: u64 = kani::any();
        let d = (pa & desc::ADDR_2M) | desc::BLOCK_ROX;
        let got = decode_block(d);
        assert!(got.is_some(), "the image block must be a valid 2 MiB block");
        let got = got.unwrap();
        assert!(got.pa == pa & desc::ADDR_2M);
        assert!(
            matches!(got.perm, Perm::Ro),
            "the SHARED guest image must never be writable"
        );
        assert!(!got.xn, "the guest must be able to fetch from its image");
    }

    /// A data leaf is **always** execute-never, whatever its address or permission — a guest can
    /// never execute from a data frame.
    #[kani::proof]
    fn data_leaves_are_always_execute_never() {
        let pa: u64 = kani::any();
        let writable: bool = kani::any();
        let attrs = if writable {
            desc::PAGE_RW
        } else {
            desc::PAGE_RO
        };
        let d = (pa & desc::ADDR_4K) | attrs;
        assert!(
            decode_page(d).unwrap().xn,
            "a data leaf must be execute-never"
        );
    }

    /// **No silent privilege escalation in the bits.** A read-only leaf can never decode as
    /// read/write, for any address — the two `S2AP` encodings are disjoint.
    #[kani::proof]
    fn readonly_never_decodes_as_writable() {
        let pa: u64 = kani::any();
        let ro = (pa & desc::ADDR_4K) | desc::PAGE_RO;
        assert!(
            matches!(decode_page(ro).unwrap().perm, Perm::Ro),
            "an RO leaf must never read back as RW"
        );
    }

    /// A table descriptor round-trips to the next-level table address, for every address.
    #[kani::proof]
    fn table_encoding_round_trips() {
        let pa: u64 = kani::any();
        let d = (pa & desc::ADDR_4K) | desc::TABLE;
        assert!(decode_table(d) == Some(pa & desc::ADDR_4K));
    }
}

/// # The Stage-2 **refinement**, proven on the shipped emitter (the first arrow)
///
/// Arrow (1) of the chain — `p2m model → leaf map` — is the isolation content of the whole metal
/// build: *which machine frames does a domain's hardware page table reach, and at what
/// permission?* `hv-sim`'s enumerator checks it over every reachable state of its configs (828,325
/// on the deep grant↔p2m sweep) and `hv-fuzz` after every dispatch. Those are **bounded**: Tier B
/// proved the grant+p2m config is the one config that can *never* saturate (`grant::map` bumps a
/// `u32` with no cap, so its reachable set is genuinely infinite), so the saturation route that
/// closed the depth axis elsewhere is unavailable here by construction.
///
/// ## The theorem
///
/// > **T.** For every model state satisfying **(P1)** `UnauthorizedForeignLink` and **(P2)** every
/// > active edge's child is allocated, and every domain `G`: the leaf map
/// > [`hv_s2::leaf_map_from_edges`] emits for `G` contains no frame that `G` neither **owns** nor
/// > holds an **active grant** for at (at least) the mapped permission — i.e.
/// > [`hv_s2::check_authorized_with`] returns `Ok`.
///
/// **T is conditional, and P1 is the load-bearing premise.** `UnauthorizedForeignLink` is what
/// makes a foreign leaf *imply* a grant; it is checked by the enumerator over every reachable state
/// and carries a Tier-B locality cutoff, but it is **not** itself a machine-checked ∀-N theorem
/// (no Verus proof discharges it — that is Arc 3b). T composes with it; T does not prove it.
/// **P2 is a separate premise P1 does not give you**: `UnauthorizedForeignLink` *skips* an edge
/// whose child is unallocated, while `check_authorized` *rejects* such a frame — so without P2, T
/// is false at `owner == None`. P2 holds because `p2m::link` requires `is_allocated(child)` and the
/// edge's own reference blocks a later free; the harnesses assume it explicitly rather than let it
/// hide.
///
/// ## What these harnesses close, and what they do not
///
/// Kani cannot construct a symbolic [`Hypervisor`] — it is heap `Vec`s, and worse, an *arbitrary
/// reachable* one. So the emitter and the checker each expose an oracle-parameterised seam
/// ([`hv_s2::leaf_map_from_edges`], [`hv_s2::check_authorized_with`]) that production calls through
/// a two-line wrapper (design-lesson #14c): these harnesses drive the **same shipped functions**
/// the metal calls, over *every* edge set, ownership assignment, grant table, permission and
/// capacity — bounded only in **edge count** and frame count. The arbitrary-*length* step is the
/// Verus mirror `hv-verify/verus/stage2_leaf_authorized.rs`.
///
/// Three complementary axes over one obligation, no one of which is the theorem alone: the
/// enumerator (real code, real reachable states, small size), Kani (real code, all values, bounded
/// length), Verus (mirror, all lengths).
///
/// ## Scope (carried verbatim from `hv_s2`'s scope boundaries — T is false without it)
///
/// The claim is **leaf-level frame reachability**, not full model reachability: the emitter maps
/// only leaves of tables the domain owns, so a legitimately shared interior node yields *no*
/// mapping beneath it — an **under**-map that fails **closed**. Superpage size, the guest-image
/// block (infrastructure, proven RO+X by `stage2_encoding`), `GuestMem` (the trusted path), and
/// VMID/table-set binding (hv-metal) are all outside T.
///
/// [`Hypervisor`]: hv_core::Hypervisor
#[cfg(kani)]
mod stage2_refinement {
    use hv_core::p2m::{DomId, Mfn};
    use hv_s2::{check_authorized_with, leaf_map_from_edges, Edge, Maps, Perm, Violation};

    /// Distinct domains the symbolic model may name. Three is the smallest world that can express
    /// the confused deputy: an owner, a mapper, and a *third* party whose grant must not count.
    const DOMS: usize = 3;
    /// Frames in the symbolic model.
    const FRAMES: usize = 4;
    /// Live page-table edges. Bounded — this is the axis the Verus mirror lifts to arbitrary N.
    const EDGES: usize = 3;

    /// Bit index into the symbolic grant *permit* table, standing in for
    /// `hv_core::grant::System::authorizes(grantor, grantee, frame, writable)`. The table is a
    /// single symbolic `u128` bitmask (`DOMS·DOMS·FRAMES·2 = 72` bits), which keeps it fully
    /// symbolic over every possible grant table while costing the solver no loop at all — an
    /// array-of-`bool` would make `kani::any` unwind 72 times before the proof even starts.
    ///
    /// Left completely free: no monotonicity between the `writable` and read-only entries is
    /// assumed, so the proof covers strictly more tables than the grant subsystem can realise.
    fn auth_idx(grantor: DomId, grantee: DomId, frame: Mfn, writable: bool) -> u32 {
        (((grantor as u32 * DOMS as u32 + grantee as u32) * FRAMES as u32 + frame) * 2)
            + u32::from(writable)
    }

    /// The symbolic world: an ownership assignment, a grant permit table, and an edge set.
    struct World {
        owners: [Option<DomId>; FRAMES],
        auth: u128,
        edges: [Edge; EDGES],
        /// Per-frame: is a leaf out of this table a SUPER span? Symbolic (M5 Arc 6a).
        spans: [bool; FRAMES],
    }

    impl World {
        /// Every field symbolic, constrained only to be *well-formed* (ids in range) — not to be
        /// reachable. Reachability enters solely as the two named premises.
        fn any() -> Self {
            let mut spans = [false; FRAMES];
            for slot in spans.iter_mut() {
                *slot = kani::any();
            }
            let mut owners = [None; FRAMES];
            for slot in owners.iter_mut() {
                let owned: bool = kani::any();
                if owned {
                    let d: DomId = kani::any();
                    kani::assume((d as usize) < DOMS);
                    *slot = Some(d);
                }
            }
            let mut edges = [(0u32, 0u32, 0u32, false, false); EDGES];
            for e in edges.iter_mut() {
                let parent: Mfn = kani::any();
                let child: Mfn = kani::any();
                kani::assume((parent as usize) < FRAMES);
                kani::assume((child as usize) < FRAMES);
                *e = (parent, kani::any(), child, kani::any(), kani::any());
            }
            World {
                owners,
                auth: kani::any(),
                edges,
                spans,
            }
        }

        /// The SPAN of a table, chosen symbolically per frame (M5 Arc 6a). Kani explores every
        /// assignment, so the refinement theorem is proven for every mix of base and super leaves —
        /// including the ones that put the same child under tables of both spans, which
        /// `leaf_map_from_edges` must then reject rather than emit two backings for.
        fn span_of(&self, m: Mfn) -> hv_s2::Span {
            if (m as usize) < FRAMES && self.spans[m as usize] {
                hv_s2::Span::Super
            } else {
                hv_s2::Span::Base
            }
        }

        fn owner_of(&self, m: Mfn) -> Option<DomId> {
            if (m as usize) < FRAMES {
                self.owners[m as usize]
            } else {
                None
            }
        }

        fn authorizes(&self, grantor: DomId, grantee: DomId, frame: Mfn, writable: bool) -> bool {
            self.auth & (1u128 << auth_idx(grantor, grantee, frame, writable)) != 0
        }

        /// **(P1) `UnauthorizedForeignLink`** — transcribed from the shape hv-core checks
        /// (`hypervisor.rs`, the page-table↔grant seam): every *cross-domain* live edge is backed
        /// by a grant from the child's owner to the domain whose table maps it, at the entry's
        /// permission. Note it *skips* an edge either end of which is unowned — which is precisely
        /// why P2 is needed separately.
        fn assume_no_unauthorized_foreign_link(&self) {
            for (parent, _slot, child, writable, _leaf) in self.edges.iter().copied() {
                let (Some(child_owner), Some(parent_owner)) =
                    (self.owner_of(child), self.owner_of(parent))
                else {
                    continue;
                };
                if child_owner != parent_owner {
                    kani::assume(self.authorizes(child_owner, parent_owner, child, writable));
                }
            }
        }

        /// **(P2) every active edge's child is allocated** — `p2m::link` refuses an unallocated
        /// child, and the reference the edge takes blocks a later free.
        fn assume_edge_children_allocated(&self) {
            for (_parent, _slot, child, _writable, _leaf) in self.edges.iter().copied() {
                kani::assume(self.owner_of(child).is_some());
            }
        }
    }

    /// **THEOREM T, on the shipped emitter.** Over every ownership assignment, grant table, edge
    /// set, target domain and table capacity: if the model state satisfies P1 and P2, then the map
    /// the emitter actually produces is authorized frame by frame — the real
    /// [`hv_s2::check_authorized_with`] finds no violation.
    ///
    /// The overflow case is *included*, not assumed away: an authorized frame that does not fit is
    /// returned as an error the metal halts on, never a silent omission. So the harness proves the
    /// disjunction "**fails loudly, or is authorized**" — there is no third outcome in which the
    /// hardware maps something the model forbids.
    #[kani::proof]
    #[kani::unwind(6)]
    fn emitted_leaf_map_is_always_authorized() {
        let w = World::any();
        let dom: DomId = kani::any();
        kani::assume((dom as usize) < DOMS);

        w.assume_no_unauthorized_foreign_link();
        w.assume_edge_children_allocated();

        // An arbitrary table capacity, including capacities too small to hold every frame.
        let cap: usize = kani::any();
        kani::assume(cap <= FRAMES);
        let mut buf = [None; FRAMES];
        // The span of each table is SYMBOLIC (M5 Arc 6a): the theorem must hold for every
        // assignment of base/super spans to parents, not just the all-base one. BOTH maps are then
        // checked, because authorization is span-independent — a mapped frame must be owned or
        // granted whatever the size of the mapping.
        let mut sup_buf = [None; FRAMES];
        if leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            dom,
            Maps {
                base: &mut buf[..cap],
                sup: &mut sup_buf[..cap],
            },
        )
        .is_ok()
        {
            for out in [&buf[..cap], &sup_buf[..cap]] {
                assert!(
                    check_authorized_with(
                        dom,
                        out,
                        |m| w.owner_of(m),
                        |g, d, f, wr| w.authorizes(g, d, f, wr),
                    )
                    .is_ok(),
                    "an emitted Stage-2 leaf map reached a frame no ownership or grant authorizes"
                );
            }
        }
    }

    /// The same theorem stated as the **isolation corollary**, because that is the sentence the
    /// project actually claims: a frame that `dom` does not own and holds no grant for is **not in
    /// the table at all** — the guest takes a translation fault rather than reaching it. Implied by
    /// T, but asserted directly so the negative form is machine-checked and not left to a reader's
    /// contraposition.
    #[kani::proof]
    #[kani::unwind(6)]
    fn an_unauthorized_frame_is_never_mapped() {
        let w = World::any();
        let dom: DomId = kani::any();
        kani::assume((dom as usize) < DOMS);
        w.assume_no_unauthorized_foreign_link();
        w.assume_edge_children_allocated();

        // The frame under scrutiny: foreign, and ungranted at either permission.
        let m: Mfn = kani::any();
        kani::assume((m as usize) < FRAMES);
        kani::assume(w.owner_of(m) != Some(dom));
        if let Some(owner) = w.owner_of(m) {
            kani::assume(!w.authorizes(owner, dom, m, false));
            kani::assume(!w.authorizes(owner, dom, m, true));
        }

        let mut out = [None; FRAMES];
        let mut sup_out = [None; FRAMES];
        if leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            dom,
            Maps {
                base: &mut out,
                sup: &mut sup_out,
            },
        )
        .is_ok()
        {
            assert!(
                out[m as usize].is_none(),
                "an unowned, ungranted frame must be a hole in the guest's Stage-2 table"
            );
        }
    }

    /// **No silent write escalation.** A frame mapped `Rw` is always backed by ownership or a
    /// *read-write* grant — a read-only grant can never produce a writable leaf. Stated separately
    /// from T because permission escalation, not mere reachability, is the sharper half of the
    /// isolation claim (and the mutation class Audit #2 called "RW for an RO leaf").
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_writable_leaf_is_never_backed_by_a_readonly_grant() {
        let w = World::any();
        let dom: DomId = kani::any();
        kani::assume((dom as usize) < DOMS);
        w.assume_no_unauthorized_foreign_link();
        w.assume_edge_children_allocated();

        let mut out = [None; FRAMES];
        let mut sup_out = [None; FRAMES];
        if leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            dom,
            Maps {
                base: &mut out,
                sup: &mut sup_out,
            },
        )
        .is_ok()
        {
            let m: Mfn = kani::any();
            kani::assume((m as usize) < FRAMES);
            if out[m as usize] == Some(Perm::Rw) {
                if let Some(owner) = w.owner_of(m) {
                    assert!(
                        owner == dom || w.authorizes(owner, dom, m, true),
                        "a writable leaf must be owned or backed by a read-write grant"
                    );
                }
            }
        }
    }

    /// Non-vacuity, kept in-tree rather than only in the arc doc: the harnesses above must be able
    /// to **fail**. Dropping P1 — the one premise the whole composition rests on — makes an
    /// unauthorized mapping reachable, so this harness asserts the violation *is* constructible:
    /// a peer's frame linked from `dom`'s table with no grant yields exactly
    /// [`Violation::UnauthorizedMapping`]. If the checker were vacuously satisfiable this would
    /// not hold.
    #[kani::proof]
    #[kani::unwind(6)]
    fn without_the_foreign_link_premise_the_checker_fires() {
        let mut owners = [None; FRAMES];
        owners[1] = Some(0); // dom0's table
        owners[2] = Some(1); // dom1's frame — never granted to dom0
        let w = World {
            owners,
            // An empty grant table: dom1 has granted dom0 nothing.
            auth: 0,
            edges: [
                (1, 0, 2, true, true),
                (1, 0, 2, true, true),
                (1, 0, 2, true, true),
            ],
            spans: [false; FRAMES],
        };
        // P2 holds; P1 deliberately does NOT (the edge is foreign and ungranted).
        let mut out = [None; FRAMES];
        let mut sup_out = [None; FRAMES];
        assert!(leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            0,
            Maps {
                base: &mut out,
                sup: &mut sup_out,
            },
        )
        .is_ok());
        assert!(
            check_authorized_with(
                0,
                &out,
                |m| w.owner_of(m),
                |g, d, f, wr| w.authorizes(g, d, f, wr)
            ) == Err(Violation::UnauthorizedMapping {
                dom: 0,
                mfn: 2,
                owner: Some(1),
                perm: Perm::Rw,
            }),
            "with P1 dropped the confused deputy must be caught — the checker is not vacuous"
        );
    }
}

/// # `UnauthorizedForeignLink` on the **real** `Hypervisor` (Arc 3b's bounded anchor)
///
/// `hv-verify/verus/foreign_link_preservation.rs` proves the preservation step
/// (`INV(s) ⇒ INV(t(s))`) for every transition class at **arbitrary** edge, grant and domain
/// count — but in the Verus dialect, against a mirror. This module is its real-code companion: it
/// builds an actual [`Hypervisor`], drives the actual `dispatch` seam with **symbolic**
/// permissions, and asserts the actual `first_cross_violation()` finds nothing.
///
/// Bounded on model size (Kani unwinds `first_cross_violation`'s scans over frames, links, grants
/// and domains), so this is the *faithfulness* anchor, not the ∀-N result — the same division of
/// labour as `grant_state_machine` versus `refcount_mismatch.rs`. What it rules out is the failure
/// mode a mirror cannot: that the transcribed guard is not the guard the shipped seam applies.
///
/// [`Hypervisor`]: hv_core::Hypervisor
#[cfg(kani)]
mod foreign_link_state_machine {
    use hv_core::p2m::PtLevel;
    use hv_core::{HvCall, Hypervisor};

    /// A two-domain world: dom0 owns a pinned `L1` table (frame 1), dom1 owns a data frame
    /// (frame 2). This is the smallest configuration in which a *cross-domain* edge — the only
    /// kind `UnauthorizedForeignLink` constrains — can exist at all (design-lesson #13f: confirm
    /// the tiny universe can build the feature's minimal witness).
    fn two_domain_world() -> Hypervisor {
        let mut hv = Hypervisor::new(2, 1, 2, 1, 1, 3);
        assert!(hv
            .dispatch(
                0,
                HvCall::DomainCreate {
                    target: 1,
                    may_create: false
                }
            )
            .is_ok());
        assert!(hv.dispatch(0, HvCall::P2mAllocate { mfn: 1 }).is_ok());
        assert!(hv
            .dispatch(
                0,
                HvCall::P2mPin {
                    mfn: 1,
                    level: PtLevel::L1
                }
            )
            .is_ok());
        assert!(hv.dispatch(1, HvCall::P2mAllocate { mfn: 2 }).is_ok());
        hv
    }

    /// **`p2m_link` preserves it, on the real seam.** dom1 offers a grant of its frame at a
    /// symbolic permission; dom0 attempts a link at an *independently* symbolic permission. Every
    /// combination is covered, including the read-write-entry-over-a-read-only-grant escalation the
    /// seam must refuse. Whether the link is accepted or rejected, the real cross-invariant must
    /// stand — a rejected link is a no-op (design-lesson #9), an accepted one is authorized.
    #[kani::proof]
    #[kani::unwind(4)]
    fn real_link_preserves_the_seam_invariant() {
        let mut hv = two_domain_world();

        let readonly: bool = kani::any();
        assert!(hv
            .dispatch(
                1,
                HvCall::GrantAccess {
                    gref: 0,
                    grantee: 0,
                    frame: 2,
                    readonly,
                }
            )
            .is_ok());

        let writable: bool = kani::any();
        let _ = hv.dispatch(
            0,
            HvCall::P2mLink {
                parent: 1,
                slot: 0,
                child: 2,
                writable,
                leaf: true,
            },
        );

        assert!(
            hv.first_cross_violation().is_none(),
            "a real cross-domain p2m_link left UnauthorizedForeignLink violated"
        );
    }

    /// **`grant_end_access` preserves it, on the real seam** — the `is_foreign_linked_by` block,
    /// exercised rather than assumed. dom1 grants read-write, dom0 links the frame, then dom1
    /// attempts to revoke the grant its peer's page table is standing on. The seam must refuse
    /// (`GrantError::InUse`); if it ever did not, the surviving edge would be unauthorized and the
    /// assertion below would fire. The symbolic `writable` covers both entry shapes.
    #[kani::proof]
    #[kani::unwind(4)]
    fn real_revoke_under_a_live_foreign_link_preserves_the_seam_invariant() {
        let mut hv = two_domain_world();
        assert!(hv
            .dispatch(
                1,
                HvCall::GrantAccess {
                    gref: 0,
                    grantee: 0,
                    frame: 2,
                    readonly: false,
                }
            )
            .is_ok());

        let writable: bool = kani::any();
        assert!(hv
            .dispatch(
                0,
                HvCall::P2mLink {
                    parent: 1,
                    slot: 0,
                    child: 2,
                    writable,
                    leaf: true,
                }
            )
            .is_ok());

        // The revoke the block exists to refuse.
        let _ = hv.dispatch(1, HvCall::GrantEndAccess { gref: 0 });

        assert!(
            hv.first_cross_violation().is_none(),
            "revoking a grant a live foreign page-table entry relies on stranded it unauthorized"
        );
    }
}
