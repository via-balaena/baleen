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

/// **Write-xor-execute on the real p2m (Phase II-1a).** W^X (`¬(writable_refs > 0 ∧
/// executable_refs > 0)`) is the leaf-permission twin of write-xor-pagetable: a per-frame
/// invariant whose entire content lives at the **0↔1 count boundary** — the acquire guard refuses
/// either reference while the other is live, and that decision reads `> 0`, not any magnitude. So
/// there is **no new unbounded axis** (unlike `RefcountMismatch`'s scalar↔`Vec`-length coupling,
/// above): the enumerator's saturation for finite configs plus the Tier-B locality cutoff close
/// the size generalization exactly as they do for `TypeConfusion`. This harness adds the
/// complementary witness on **real code** — that a symbolic pair of leaves onto one frame can never
/// leave it both writable- and executable-mapped — which is *complete* for W^X precisely because
/// the boundary, not the magnitude, is the whole property (design-lesson #50: no Verus mirror where
/// there is no unbounded `Vec` axis).
#[cfg(kani)]
mod p2m_write_xor_execute {
    use hv_core::p2m::{P2mError, PtLevel, System};

    /// The dual-alias shape W^X exists to forbid: a frame mapped **writable** by one leaf, then a
    /// second leaf onto the *same* frame with a symbolic `(writable, execute)`. Whatever the guest
    /// chooses for the second leaf — writable, executable (the write-then-execute shellcode alias),
    /// or read-only — the real `first_violation()` must find nothing. A refused link is a
    /// legitimate no-op; either way the frame is never simultaneously writable- and
    /// executable-mapped. The pre-state is concrete and the second leaf symbolic, which keeps the
    /// path count (and so the solver) small while covering the whole W^X boundary from the writable
    /// side; [`executable_frame_stays_wx_under_a_symbolic_leaf`] covers the executable side.
    #[kani::proof]
    #[kani::unwind(5)]
    fn writable_frame_stays_wx_under_a_symbolic_leaf() {
        let mut s = System::new(1, 2);
        s.allocate(0, 0).unwrap(); // the root table
        s.allocate(0, 1).unwrap(); // the shared child frame
        s.pin(0, 0, PtLevel::L1).unwrap();
        s.link(0, 0, 0, 1, true, true, false).unwrap(); // frame 1 mapped writable

        let (w, x): (bool, bool) = (kani::any(), kani::any());
        let _ = s.link(0, 0, 1, 1, w, true, x);

        assert!(
            s.first_violation().is_none(),
            "a symbolic second leaf onto a writable frame left W^X violated"
        );
    }

    /// The executable-side mirror: a frame mapped **executable**, then a symbolic second leaf onto
    /// it — a `writable` choice must be refused (W^X), never producing a writable+executable frame.
    #[kani::proof]
    #[kani::unwind(5)]
    fn executable_frame_stays_wx_under_a_symbolic_leaf() {
        let mut s = System::new(1, 2);
        s.allocate(0, 0).unwrap();
        s.allocate(0, 1).unwrap();
        s.pin(0, 0, PtLevel::L1).unwrap();
        s.link(0, 0, 0, 1, false, true, true).unwrap(); // frame 1 mapped executable

        let (w, x): (bool, bool) = (kani::any(), kani::any());
        let _ = s.link(0, 0, 1, 1, w, true, x);

        assert!(
            s.first_violation().is_none(),
            "a symbolic second leaf onto an executable frame left W^X violated"
        );
    }

    /// **Teeth (non-vacuity), on real code.** A writable leaf takes; an executable leaf onto the
    /// same frame is then refused with `WxConflict`. Confirms the guard the preservation harness
    /// relies on actually fires, rather than the frame never becoming writable in the first place.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_writable_frame_refuses_an_executable_leaf() {
        let mut s = System::new(1, 2);
        s.allocate(0, 0).unwrap();
        s.allocate(0, 1).unwrap();
        s.pin(0, 0, PtLevel::L1).unwrap();
        s.link(0, 0, 0, 1, true, true, false).unwrap(); // a writable leaf takes
        assert_eq!(
            s.link(0, 0, 1, 1, false, true, true),
            Err(P2mError::WxConflict),
            "an executable leaf onto a writable-mapped frame must be refused"
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
    use hv_s2::arm64::{
        block_leaf_attrs, decode_block, decode_page, decode_table, desc, leaf_access_xn,
        page_leaf_attrs, Decoded,
    };
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

    /// A **data** leaf (writable or read-only — never a read-*execute* leaf) is always execute-never,
    /// whatever its address or permission. Post-II-1b only a `Perm::Rx` leaf drops `XN`; `Rw`/`Ro`
    /// data stays execute-never, so this still holds.
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

    /// **Phase II-1b — a read-execute (`Rx`) leaf decodes read-only AND executable**, at both spans,
    /// for every address. Executability (the absent `XN`) is the model's, and it never comes with
    /// write access — `Rx` is read-only, so it is never W+X.
    #[kani::proof]
    fn rx_leaf_decodes_executable_and_read_only() {
        let pa: u64 = kani::any();
        let page = decode_page((pa & desc::ADDR_4K) | desc::PAGE_RX).unwrap();
        assert!(!page.xn, "an Rx page must be executable");
        assert!(
            matches!(page.perm, Perm::Ro),
            "an Rx page is read-only, never W+X"
        );
        let block = decode_block((pa & desc::ADDR_2M) | desc::BLOCK_RX).unwrap();
        assert!(!block.xn, "an Rx block must be executable");
        assert!(
            matches!(block.perm, Perm::Ro),
            "an Rx block is read-only, never W+X"
        );
    }

    /// **THE II-1b FIDELITY THEOREM — the emitted execute bit follows the model, and the declared
    /// exemption is its SOLE writable+executable source.** Over every `(perm, wx_exempt)`, the
    /// shared [`leaf_access_xn`] derivation the emitter and verifier both trust produces a
    /// writable-AND-executable leaf (`access == Rw && !xn`) **iff** the model leaf is writable and
    /// its window is W^X-exempt; a read-only or read-execute leaf is never writable-executable, and
    /// a read-only (`Ro`) leaf is never executable. So "no W+X descriptor except the one declared
    /// relaxation" is machine-checked on the shipped code, not argued.
    #[kani::proof]
    fn the_exemption_is_the_sole_writable_and_executable_leaf() {
        let wx_exempt: bool = kani::any();
        for perm in [Perm::Ro, Perm::Rw, Perm::Rx] {
            let (access, xn) = leaf_access_xn(perm, wx_exempt);
            let writable_and_executable = matches!(access, Perm::Rw) && !xn;
            assert!(
                writable_and_executable == (matches!(perm, Perm::Rw) && wx_exempt),
                "a writable+executable leaf arises iff the declared exemption applies"
            );
            // Executability follows the model: executable iff read-execute, or the exemption on a
            // writable leaf. A read-only leaf is never executable.
            assert!(
                (!xn) == (matches!(perm, Perm::Rx) || (matches!(perm, Perm::Rw) && wx_exempt)),
                "the emitted execute bit must follow the model's leaf permission"
            );
            if matches!(perm, Perm::Ro) {
                assert!(xn, "a read-only data leaf is never executable");
            }
        }
    }

    /// **THE II-1b EMITTER-FIDELITY THEOREM — the descriptor bits `encode` WRITES decode to exactly
    /// the seam, over every address, permission, and the symbolic W^X exemption.** The
    /// [`the_exemption_is_the_sole_writable_and_executable_leaf`] theorem proves the *decode* seam
    /// [`leaf_access_xn`], and [`hv_s2::arm64::verify_encoding`] checks the emitted table against it
    /// — but the emitter's own descriptor selection was, until II-1b's `#14c` refactor, an inline
    /// `match` no ∀ proof ever ran (only concrete golden tests + the boot-time `verify_encoding`
    /// touched it). `encode` now selects its bits by calling the named emit-seams
    /// [`page_leaf_attrs`] / [`block_leaf_attrs`], so this harness drives the very functions the
    /// emitter runs and proves — over ALL 2⁶⁴ addresses — that decoding what `encode` writes
    /// (`pa | page_leaf_attrs(perm)`, `pa | block_leaf_attrs(perm, exempt)`) recovers exactly what
    /// the decode seam [`leaf_access_xn`] prescribes. So the descriptor *words the MMU walks*, not
    /// just the verifier's expectation, follow the model's execute bit. Emit-seam and decode-seam
    /// stay INDEPENDENT derivations (the #36 cross-check); this proves they coincide. Base leaves
    /// are never exempt (the emitter passes `false`); the super window carries the declared exemption.
    #[kani::proof]
    fn encode_leaf_descriptors_follow_the_seam() {
        let pa: u64 = kani::any();
        let wx_exempt: bool = kani::any();
        for perm in [Perm::Ro, Perm::Rw, Perm::Rx] {
            // Base leaf (`L3` page): the emitter passes `false` — never W^X-exempt.
            let (base_access, base_xn) = leaf_access_xn(perm, false);
            assert!(
                decode_page((pa & desc::ADDR_4K) | page_leaf_attrs(perm))
                    == Some(Decoded {
                        pa: pa & desc::ADDR_4K,
                        perm: base_access,
                        xn: base_xn,
                    }),
                "the base-leaf bits encode writes must decode to exactly leaf_access_xn(perm, false)"
            );

            // Super leaf (`L2` block): the emitter passes the declared exemption.
            let (sup_access, sup_xn) = leaf_access_xn(perm, wx_exempt);
            assert!(
                decode_block((pa & desc::ADDR_2M) | block_leaf_attrs(perm, wx_exempt))
                    == Some(Decoded {
                        pa: pa & desc::ADDR_2M,
                        perm: sup_access,
                        xn: sup_xn,
                    }),
                "the super-leaf bits encode writes must decode to exactly leaf_access_xn(perm, exempt)"
            );
        }
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
    use hv_s2::{
        check_authorized_with, leaf_map_from_edges, Edge, MapError, Maps, Perm, Violation,
    };

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
            let mut edges = [(0u32, 0u32, 0u32, false, false, false); EDGES];
            for e in edges.iter_mut() {
                let parent: Mfn = kani::any();
                let child: Mfn = kani::any();
                kani::assume((parent as usize) < FRAMES);
                kani::assume((child as usize) < FRAMES);
                // The trailing `execute` bit is symbolic too — T is execute-independent (as it is
                // span-independent), so proving it over every execute assignment is free coverage
                // and confirms the write-xor-execute axis threads through without weakening T.
                *e = (
                    parent,
                    kani::any(),
                    child,
                    kani::any(),
                    kani::any(),
                    kani::any(),
                );
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
            for (parent, _slot, child, writable, _leaf, _execute) in self.edges.iter().copied() {
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
            for (_parent, _slot, child, _writable, _leaf, _execute) in self.edges.iter().copied() {
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
                (1, 0, 2, true, true, false),
                (1, 0, 2, true, true, false),
                (1, 0, 2, true, true, false),
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

    // ─── Phase I-4: the span-conflict boundary, decided then proven ────────────────────────────
    //
    // `hv-core` PERMITS one frame being a leaf at two different spans (a base-level table and a
    // super-level table both leaf-linking the same child): `MislevelledLink` constrains only an
    // *interior* entry's child, never a leaf's. The emitter cannot represent it — each span has its
    // own disjoint host-PA window, so one `Mfn` would need two backings — so `leaf_map_from_edges`
    // fails **loud** (`MapError::SpanConflict`) and `check_all` classifies it `OutOfDomain`, NOT a
    // `Violation` (the enumerator reaches it in 6 hypercalls; folding it into `Violation` would flag
    // a legal state).
    //
    // The I-4 decision is that this resting place is CORRECT — a frame at two spans is a
    // representability limit that fails closed, not an isolation hazard, so `hv-core` need not (and
    // should not, #8/#44) carry a guard against it. These harnesses prove that decision sound on the
    // shipped emitter: the fail-loud is TOTAL and the out-of-domain classification conceals nothing.
    // The ∀-edge-count companion is `verus/stage2_leaf_authorized.rs::a_span_conflict_frame_is_authorized`.

    /// **Detection is complete — the fail-loud is TOTAL.** Whenever the real `leaf_map_from_edges`
    /// returns `Ok`, no frame is left mapped at BOTH spans. Contrapositive: a state that would
    /// produce a span-conflict can never be silently accepted and canonicalised to one span — it
    /// must fail loud. Over every ownership assignment, span assignment, edge set and capacity.
    #[kani::proof]
    #[kani::unwind(6)]
    fn an_accepted_map_has_no_span_conflict() {
        let w = World::any();
        let dom: DomId = kani::any();
        kani::assume((dom as usize) < DOMS);
        let cap: usize = kani::any();
        kani::assume(cap <= FRAMES);

        let mut base = [None; FRAMES];
        let mut sup = [None; FRAMES];
        if leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            dom,
            Maps {
                base: &mut base[..cap],
                sup: &mut sup[..cap],
            },
        )
        .is_ok()
        {
            let m: Mfn = kani::any();
            kani::assume((m as usize) < cap);
            assert!(
                !(base[m as usize].is_some() && sup[m as usize].is_some()),
                "an accepted Stage-2 emission left a frame mapped at BOTH spans — a silent span-conflict"
            );
        }
    }

    /// **Detection is sound — no false conflict.** When the emitter reports
    /// `Err(SpanConflict { mfn })`, that frame really is mapped at both spans (both maps hold it).
    /// So the `OutOfDomain::SpanConflict` verdict never fires on a state that is *not* a conflict —
    /// the refinement's domain is not silently narrowed by a spurious rejection.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_reported_span_conflict_is_real() {
        let w = World::any();
        let dom: DomId = kani::any();
        kani::assume((dom as usize) < DOMS);
        let cap: usize = kani::any();
        kani::assume(cap <= FRAMES);

        let mut base = [None; FRAMES];
        let mut sup = [None; FRAMES];
        let verdict = leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            dom,
            Maps {
                base: &mut base[..cap],
                sup: &mut sup[..cap],
            },
        );
        // On `SpanConflict` the post-pass runs *after* the whole edge loop, so both maps are fully
        // built — the named frame is genuinely resident in each.
        if let Err(MapError::SpanConflict { mfn }) = verdict {
            assert!(
                base[mfn as usize].is_some() && sup[mfn as usize].is_some(),
                "SpanConflict named a frame that is not actually a leaf at two spans"
            );
        }
    }

    /// **The out-of-domain classification hides no `Violation`.** Under P1 and P2, a span-conflict
    /// state's emitted maps reach only frames the domain owns or holds a grant for — at BOTH spans.
    /// So routing a two-span frame to `OutOfDomain` rather than `Violation` cannot mask an
    /// unauthorized reach: the conflict names an authorized frame, exactly because authorization is
    /// span-independent. This is the real-code companion to the ∀-N Verus lemma; it closes T's
    /// silence on the `Err` branch (T asserts authorization only when the emitter returns `Ok`).
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_span_conflict_state_maps_only_authorized_frames() {
        let w = World::any();
        let dom: DomId = kani::any();
        kani::assume((dom as usize) < DOMS);
        w.assume_no_unauthorized_foreign_link();
        w.assume_edge_children_allocated();
        let cap: usize = kani::any();
        kani::assume(cap <= FRAMES);

        let mut base = [None; FRAMES];
        let mut sup = [None; FRAMES];
        // Both maps are fully built whether the call ends in `Ok` or `Err(SpanConflict)` (the
        // conflict is a post-pass), so this assertion covers the rejected state too.
        if let Err(MapError::SpanConflict { .. }) = leaf_map_from_edges(
            &w.edges,
            |m| w.owner_of(m),
            |p| Some(w.span_of(p)),
            dom,
            Maps {
                base: &mut base[..cap],
                sup: &mut sup[..cap],
            },
        ) {
            for out in [&base[..cap], &sup[..cap]] {
                assert!(
                    check_authorized_with(
                        dom,
                        out,
                        |m| w.owner_of(m),
                        |g, d, f, wr| w.authorizes(g, d, f, wr),
                    )
                    .is_ok(),
                    "a rejected span-conflict state still mapped a frame no ownership or grant authorizes"
                );
            }
        }
    }

    /// **Non-vacuity + teeth: a real span-conflict IS constructible and IS caught.** Frame 2 is a
    /// leaf under table 1 (a BASE-span parent) and under table 3 (a SUPER-span parent), both owned
    /// by dom0. The emitter must reject it as `SpanConflict { mfn: 2 }` — proving the harnesses
    /// above are not vacuously satisfied by "no conflict is ever reachable", and that the post-pass
    /// genuinely fires (drop it and this fails).
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_constructed_span_conflict_is_rejected() {
        let mut owners = [None; FRAMES];
        owners[1] = Some(0); // a base-level table of dom0
        owners[2] = Some(0); // the shared child frame
        owners[3] = Some(0); // a super-level table of dom0
        let mut spans = [false; FRAMES];
        spans[3] = true; // leaves out of table 3 are SUPER; out of table 1 are BASE
        let w = World {
            owners,
            auth: 0,
            edges: [
                (1, 0, 2, true, true, false), // dom0 base-leafs frame 2
                (3, 0, 2, true, true, false), // dom0 super-leafs the SAME frame 2
                (1, 0, 2, true, true, false), // benign duplicate — must not change the verdict
            ],
            spans,
        };
        let mut base = [None; FRAMES];
        let mut sup = [None; FRAMES];
        assert!(
            leaf_map_from_edges(
                &w.edges,
                |m| w.owner_of(m),
                |p| Some(w.span_of(p)),
                0,
                Maps {
                    base: &mut base,
                    sup: &mut sup,
                },
            ) == Err(MapError::SpanConflict { mfn: 2 }),
            "a frame leafed under both a base and a super table must fail loud, not be canonicalised"
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
        let mut hv = Hypervisor::new(2, 1, 2, 1, 1, 3, 2);
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
                execute: false,
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
                    execute: false,
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

/// # The **device pass-through region** under the refinement theorem (M5 Phase I-3)
///
/// The RAM refinement `T` (`stage2_refinement`) is *edge-driven*: every mapped frame is owned or
/// granted, proven by walking `p2m` edges. The device MMIO window is **p2m-unbacked** — no edge
/// describes it, identity-mapped `IPA == PA`, Device-nGnRnE, execute-never, 2 MiB blocks — so `T`
/// and [`hv_s2::check_authorized_with`] say nothing about it, and until now its isolation rested on
/// [`hv_s2::arm64::Layout::validate`] passing over the *one concrete metal layout* plus a runtime
/// decode in `verify_encoding`. That is a fail-**silent** surface (a hole would map a guest into RAM
/// through the device window, or decode MMIO as cacheable Normal memory) resting on a runtime check,
/// not a theorem.
///
/// This module brings it under a theorem. The shape differs from `T` because the region is not an
/// authorization property of edges — it is a **disjointness + attributes** property of the `Layout`
/// and emitter, which is the refinement *absorbing the shape mismatch* (design-lesson #44), proven
/// by composition rather than by widening the p2m-level checker:
///
/// > **T_dev.** If [`Layout::validate`] returns `Ok`, then **(i)** every emitted device block is
/// > disjoint in **both** IPA and PA from every RAM leaf the emitter can emit (data `L3`, super
/// > `L2`), and **(ii)** every emitted device block is Device-nGnRnE + execute-never + identity.
///
/// ## Why Kani alone closes it — no Verus mirror, no fidelity gap
///
/// Unlike `T` (∀-N over an *unbounded* edge/frame population, which forced the Verus mirror), the
/// device region has **no unbounded axis**: the region count is structurally **4**, blocks per
/// window are bounded by one `L2` (≤ `TABLE_ENTRIES`), and a leaf beyond `TABLE_ENTRIES` is
/// `FrameOutOfRange`. So Kani closes it **on the real shipped `hv_s2::arm64` code over every address**
/// — a strictly stronger result than `T`'s managed-mirror gap (design-lesson #20b: Kani for the
/// bounded-but-real, Verus only for the genuinely-infinite axis). The harnesses drive the real
/// [`Layout::validate`] / [`Layout::regions`] and the real `frame_pa`/`super_pa` address derivations,
/// so proving them is proving a property of the emitter that runs.
///
/// ## Declared parameter (design-lesson #44b)
///
/// The symbolic-layout harnesses fix `frame_size = 0x1000` (the system's 4 KiB granule — a genuine
/// constant on the metal, not a free variable) and bound region bases to the 48-bit PA/IPA range the
/// descriptor masks already enforce. Both keep `Layout::validate`'s unchecked `b + blen` interval
/// arithmetic overflow-free while remaining faithful to every layout the emitter actually builds.
///
/// [`Layout`]: hv_s2::arm64::Layout
/// [`Layout::validate`]: hv_s2::arm64::Layout::validate
/// [`Layout::regions`]: hv_s2::arm64::Layout::regions
#[cfg(kani)]
mod stage2_device_region {
    use hv_s2::arm64::{
        decode_device_block, desc, frame_ipa, frame_pa, super_ipa, super_pa, DecodedDevice, Layout,
        BLOCK_SIZE, TABLE_ENTRIES,
    };

    /// The 4 KiB granule (see the module's declared-parameter note).
    const FRAME_SIZE: u64 = 0x1000;

    /// A symbolic [`Layout`]: every field the disjointness proof reads is free, bounded only enough
    /// to keep `validate`'s interval arithmetic overflow-free (bases in the 48-bit range, spans well
    /// under it). The table PAs `validate`/`regions` never read are pinned to `0`.
    fn symbolic_layout() -> Layout {
        // Bases < 2^44 and every span < 2^30, so `base + span < 2^45` — no `u64` overflow anywhere
        // in `validate`, while covering every region placement the metal can produce.
        let bounded = || -> u64 {
            let a: u64 = kani::any();
            kani::assume(a < (1u64 << 44));
            a
        };
        // A whole number of 2 MiB device blocks, at most one full `L2` (1 GiB).
        let dev_blocks: u64 = kani::any();
        kani::assume(dev_blocks <= TABLE_ENTRIES as u64);
        // At most one full super `L2` worth of backed frames.
        let sup_frames: u64 = kani::any();
        kani::assume(sup_frames <= TABLE_ENTRIES as u64);
        let guest_image_pa = if kani::any() { Some(bounded()) } else { None };
        Layout {
            l1_pa: 0,
            l2_code_pa: 0,
            l2_data_pa: 0,
            l3_data_pa: 0,
            l2_sup_pa: 0,
            l2_dev_pa: 0,
            guest_image_pa,
            data_ipa_base: bounded(),
            data_pa_base: bounded(),
            frame_size: FRAME_SIZE,
            sup_ipa_base: bounded(),
            sup_pa_base: bounded(),
            device_base: bounded(),
            device_len: dev_blocks * BLOCK_SIZE,
            sup_wx_exempt: kani::any(),
            sup_frames,
        }
    }

    /// **T_dev (ii) — attributes.** For *every* output address, the device-block encoding decodes to
    /// exactly an identity PA, execute-never, Device-nGnRnE — the one descriptor kind the
    /// `stage2_encoding` bit-precise family did not yet cover. The `xn: true` and the identity PA are
    /// the whole isolation content: a device block that decoded as executable, or at the wrong PA, is
    /// precisely the failure `verify_encoding`'s `l2_dev` check exists to catch, now proven over all
    /// 2⁶⁴ addresses rather than golden fixtures.
    #[kani::proof]
    fn device_block_encodes_as_device_ngnrne_xn_identity() {
        let pa: u64 = kani::any();
        let d = (pa & desc::ADDR_2M) | desc::BLOCK_DEVICE;
        assert!(
            decode_device_block(d)
                == Some(DecodedDevice {
                    pa: pa & desc::ADDR_2M,
                    xn: true,
                }),
            "a device block must decode to an identity PA, execute-never and Device-nGnRnE"
        );
    }

    /// **T_dev (ii) — the confusion caught.** No Normal-memory descriptor is *ever* mistaken for a
    /// device block, for any word: a `MemAttr` of Normal Write-Back (`0b1111`, what every RAM
    /// leaf/block carries) makes [`decode_device_block`] return `None`. This is the bit-level guard
    /// that a RAM block can never masquerade as MMIO — the inverse of the attribute above.
    #[kani::proof]
    fn normal_memory_never_decodes_as_a_device_block() {
        let d: u64 = kani::any();
        // The block type bits and Normal-WB memory attributes — a valid Normal-memory block/leaf.
        kani::assume(d & 0b11 == desc::BLOCK);
        kani::assume((d >> 2) & 0b1111 == 0b1111);
        assert!(
            decode_device_block(d).is_none(),
            "Normal-memory attributes must never decode as Device-nGnRnE"
        );
    }

    /// **T_dev (i) — the disjointness gate is total.** Over every symbolic `Layout`, if the real
    /// [`Layout::validate`] returns `Ok`, then *every* present region pair is in distinct `L1`
    /// entries and disjoint in both IPA and PA. This proves `validate`'s pairwise loop leaves no pair
    /// unchecked — the exact regression `regions()` replaced three open-coded pairs to prevent (M5
    /// Arc 6b) — for an arbitrary pair `(i, j)`, not just the four the metal happens to build.
    #[kani::proof]
    #[kani::unwind(5)]
    fn validate_ok_implies_regions_pairwise_disjoint() {
        let l = symbolic_layout();
        kani::assume(l.validate().is_ok());
        let regions = l.regions();

        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < regions.len());
        kani::assume(j < regions.len());
        kani::assume(i < j);

        if let (Some((l1a, ipa_a, pa_a, span_a)), Some((l1b, ipa_b, pa_b, span_b))) =
            (regions[i], regions[j])
        {
            assert!(
                l1a != l1b,
                "a validated layout must place every region in a distinct L1 entry"
            );
            assert!(
                !(ipa_a < ipa_b + span_b && ipa_b < ipa_a + span_a),
                "a validated layout must have pairwise-disjoint IPA windows"
            );
            assert!(
                !(pa_a < pa_b + span_b && pa_b < pa_a + span_a),
                "a validated layout must have pairwise-disjoint PA windows"
            );
        }
    }

    /// **T_dev (i) — the isolation corollary.** The sentence the project actually claims: a validated
    /// layout emits *no device block that aliases any RAM leaf*, in either address space. For an
    /// arbitrary emitted device block `k` and an arbitrary emitted data leaf `m` and super leaf `s`,
    /// the real address derivations (`frame_pa`/`frame_ipa`/`super_pa`/`super_ipa`) never coincide
    /// with the device block's identity address. Implied by the window disjointness above composed
    /// with "each leaf lies within its region's window", but asserted directly so the isolation form
    /// — no RAM reachable through the device window, no device page overlapping RAM — is
    /// machine-checked and not left to a reader's composition.
    #[kani::proof]
    #[kani::unwind(5)]
    fn validate_ok_implies_device_disjoint_from_ram_leaves() {
        let l = symbolic_layout();
        // A device region is present.
        kani::assume(l.device_len >= BLOCK_SIZE);
        kani::assume(l.validate().is_ok());

        // An arbitrary emitted device block — identity, so its IPA and PA are the same address.
        let k: u64 = kani::any();
        kani::assume(k < TABLE_ENTRIES as u64);
        kani::assume(k * BLOCK_SIZE < l.device_len);
        let dev = l.device_base + k * BLOCK_SIZE;

        // …never coincides with an emitted data leaf (any representable frame is inside the data
        // window, whose span validate checked disjoint from the device window).
        let m: u32 = kani::any();
        kani::assume((m as u64) < TABLE_ENTRIES as u64);
        assert!(
            dev != frame_pa(&l, m),
            "a device block PA aliases a data-leaf PA — a guest could reach RAM through MMIO"
        );
        assert!(
            dev != frame_ipa(&l, m),
            "a device block IPA aliases a data-leaf IPA"
        );

        // …never coincides with an emitted super-span leaf (only backed frames, `s < sup_frames`,
        // are emitted, matching the span validate checked).
        let s: u32 = kani::any();
        kani::assume((s as u64) < l.sup_frames);
        assert!(
            dev != super_pa(&l, s),
            "a device block PA aliases a super-span-leaf PA"
        );
        assert!(
            dev != super_ipa(&l, s),
            "a device block IPA aliases a super-span-leaf IPA"
        );
    }
}

/// **∀-StreamID stream-table default-deny** — the SMMU arc, rung 2.
///
/// The device path's isolation decision is made in one place: the SMMUv3 **stream table**. A
/// transaction carries a StreamID, the SMMU indexes the table with it, and the entry decides abort /
/// bypass / translate. The property the rung is about is a universal one —
///
/// > ∀ StreamID: unless this hypervisor deliberately bound it, the transaction aborts
///
/// — over a space (2³² StreamIDs, 2⁶⁴ entry words) that no boot test and no enumerator reaches. These
/// harnesses close it on the shipped [`hv_s2::smmu`] builder.
///
/// **Bounded axis, stated plainly** (ledger item B): the *table size* here is small and concrete —
/// `log2size <= 2`, i.e. at most four entries — while the StreamID and the entry words are fully
/// symbolic. So this is "∀ values, bounded size", the same shape as the `DOMS=3 / FRAMES=4` grant
/// proofs. The size axis is closed differently and more weakly: the builder's own refusals
/// (`TableTooSmall`, `SidOutOfRange`) are size-generic code, and `denies_every_stream` is run on the
/// *real* table by the metal on every SMMU boot.
///
/// **And what these do NOT prove, which is the thing worth saying loudest:** every theorem here is
/// about the bytes the builder writes, not about the SMMU that reads them. A green Kani run is fully
/// compatible with "the device never reached the stream table at all", which is precisely how an
/// ∀-StreamID deny passes vacuously. The hardware arrow is discharged by the metal's *through-STE
/// positive control* — the same device, the same boot, aborted with a zeroed STE and landing with a
/// bypass STE — and by nothing here.
#[cfg(kani)]
mod smmu_stream_table {
    use hv_s2::smmu::{
        bind, bypass_ste, decode, deny_ste, strtab_base, strtab_base_cfg, table_words, unbind,
        verdict, StreamTableError, StreamVerdict, BUS0_LOG2SIZE, MAX_LOG2SIZE, STE_WORDS,
    };

    /// The largest table the harnesses instantiate: 4 entries (32 words). Symbolic `log2size` ranges
    /// over `0..=2`, so every configured size that fits this storage is covered at once.
    const MAX_HARNESS_LOG2: u32 = 2;
    const WORDS: usize = (1 << MAX_HARNESS_LOG2) * STE_WORDS;

    /// A symbolic table size this storage can actually hold.
    fn any_log2() -> u32 {
        let n: u32 = kani::any();
        kani::assume(n <= MAX_HARNESS_LOG2);
        n
    }

    /// **Deny by default, ∀ StreamID, at the size actually deployed.** The harnesses in this module
    /// otherwise run on a 4-entry table — small enough to keep the symbolic-index reasoning cheap, and
    /// honest about it. But the *deployed* table is `2^BUS0_LOG2SIZE` = 256 entries, and a property
    /// proven only at a size nothing ships is a property about nothing shipped. This one closes that
    /// exactly: `hv_s2::smmu::BUS0_LOG2SIZE` is the same constant `hv-metal` allocates and configures
    /// from, so the size proven here and the size deployed cannot drift.
    /// The verdict is asserted **by reason**, not merely as `!permits()`. A table whose storage were
    /// smaller than its configured size would also deny every StreamID — via `OutOfRange` — so a bare
    /// `!permits()` here would pass just as happily on a mis-sized table, which is the
    /// `an_under_allocated_table_…` failure wearing this harness as a disguise. Requiring `Invalid`
    /// (i.e. `STE.V == 0`, the zeroed entry) inside the range and `OutOfRange` only outside it is what
    /// makes this a statement about the deny-by-default entry rather than about an allocation mistake.
    #[kani::proof]
    fn the_deployed_stream_table_denies_every_streamid() {
        let words = [0u64; (1 << BUS0_LOG2SIZE) * STE_WORDS];
        let sid: u32 = kani::any();
        let v = verdict(&words, BUS0_LOG2SIZE, sid);
        assert!(
            !v.permits(),
            "the deployed 256-entry stream table must deny every StreamID before anything is bound"
        );
        if (sid as u64) < (1u64 << BUS0_LOG2SIZE) {
            assert!(
                v == StreamVerdict::Invalid,
                "in-range StreamIDs must be denied by a zeroed ENTRY, not by a mis-sized table"
            );
        } else {
            assert!(v == StreamVerdict::OutOfRange);
        }
    }

    /// **Deny by default, ∀ StreamID.** A zeroed stream table — which is what `.bss` already holds,
    /// and what `init_deny` restores — permits *no* StreamID, for every one of the 2³² values a
    /// transaction can carry and every table size the storage supports.
    ///
    /// The `assert` is on `permits()`, not on a particular verdict, so the three denial arms
    /// (`OutOfRange`, `Invalid`, `ConfigAbort`) are covered by one statement and a future fourth
    /// cannot slip past by being a new variant.
    #[kani::proof]
    fn zeroed_stream_table_denies_every_streamid() {
        let words = [0u64; WORDS];
        let log2 = any_log2();
        let sid: u32 = kani::any();
        let v = verdict(&words, log2, sid);
        assert!(
            !v.permits(),
            "a zeroed stream table must deny every StreamID"
        );
        // By reason, for the same reason as the deployed-size harness above: an in-range
        // StreamID must be denied by its zeroed ENTRY, so this cannot pass on a table too small for
        // the size it was handed.
        if (sid as u64) < (1u64 << log2) {
            assert!(v == StreamVerdict::Invalid);
        } else {
            assert!(v == StreamVerdict::OutOfRange);
        }
    }

    /// **Binding is StreamID-specific, ∀ other StreamID.** After binding exactly one StreamID to a
    /// bypass STE, every *other* StreamID is still denied — and the bound one is permitted.
    ///
    /// The second assertion is the non-vacuity half and it is not optional: without it the harness
    /// passes if `bind` writes nothing at all, which is the exact failure mode ⑦ found in the Verus
    /// `Obs` split (a green proof over a surface that cannot exhibit the flow). This is also the
    /// machine-checked form of the metal's third phase — a permissive STE at a *neighbouring*
    /// StreamID does not admit the device.
    #[kani::proof]
    fn binding_one_stream_leaves_every_other_denied() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let bound: u32 = kani::any();
        kani::assume((bound as u64) < (1u64 << log2));

        assert!(bind(&mut words, log2, bound, bypass_ste()).is_ok());
        assert!(
            verdict(&words, log2, bound).permits(),
            "the deliberately bound StreamID must be permitted — otherwise the deny below is vacuous"
        );

        let other: u32 = kani::any();
        kani::assume(other != bound);
        assert!(
            !verdict(&words, log2, other).permits(),
            "binding one StreamID must not permit any other"
        );
    }

    /// **`unbind` is a true inverse, ∀ StreamID.** After binding and unbinding, the table denies
    /// every StreamID again — including the one that was bound. This is what makes the metal's
    /// bypass→deny transition a *restoration* of the default rather than a different state that
    /// merely happens to abort.
    #[kani::proof]
    fn unbind_restores_deny_for_every_streamid() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let bound: u32 = kani::any();
        kani::assume((bound as u64) < (1u64 << log2));

        assert!(bind(&mut words, log2, bound, bypass_ste()).is_ok());
        assert!(unbind(&mut words, log2, bound).is_ok());

        let sid: u32 = kani::any();
        assert!(
            !verdict(&words, log2, sid).permits(),
            "an unbound stream table must deny every StreamID"
        );
    }

    /// **An out-of-range bind writes nothing, ∀ StreamID beyond the table.** The refusal is not
    /// merely reported: the storage is unchanged, so a mis-sized StreamID cannot authorise some
    /// *other* stream by wrapping or truncating into it.
    ///
    /// Checked over a symbolic word index rather than a loop, so it is a statement about every word
    /// of the table with no unwinding.
    #[kani::proof]
    fn an_out_of_range_bind_changes_no_word() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let sid: u32 = kani::any();
        kani::assume((sid as u64) >= (1u64 << log2));

        assert!(bind(&mut words, log2, sid, bypass_ste()) == Err(StreamTableError::SidOutOfRange));

        let i: usize = kani::any();
        kani::assume(i < WORDS);
        assert!(words[i] == 0, "a refused bind must not write any word");
    }

    /// **A bind touches only its own entry, ∀ word outside it.** The 8 words of `sid`'s STE change;
    /// nothing else does. A bind that wrote past its entry would silently validate the *next*
    /// StreamID — a fail-open the `zeroed_…` harness above cannot see, because it runs on a table
    /// nobody has bound.
    #[kani::proof]
    fn a_bind_touches_only_its_own_entry() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let bound: u32 = kani::any();
        kani::assume((bound as u64) < (1u64 << log2));
        let off = (bound as usize) * STE_WORDS;

        assert!(bind(&mut words, log2, bound, bypass_ste()).is_ok());

        let i: usize = kani::any();
        kani::assume(i < WORDS);
        kani::assume(i < off || i >= off + STE_WORDS);
        assert!(words[i] == 0, "a bind must not write outside its own STE");
    }

    /// **A table configured larger than it was allocated denies everything, ∀ StreamID.** This is the
    /// one way a linear stream table fails *open* on real hardware: `STRTAB_BASE_CFG.LOG2SIZE` says
    /// 2ⁿ entries, the allocation holds fewer, and the SMMU fetches STEs from whatever follows it.
    /// The builder refuses to model that as anything but a denial — and [`bind`] refuses to create
    /// it, so the metal cannot reach the state in the first place.
    #[kani::proof]
    fn an_under_allocated_table_denies_every_streamid() {
        // Storage for one entry, configured for two or four.
        let mut words = [0u64; STE_WORDS];
        let log2: u32 = kani::any();
        kani::assume(log2 >= 1 && log2 <= MAX_HARNESS_LOG2);

        let sid: u32 = kani::any();
        assert!(
            verdict(&words, log2, sid) == StreamVerdict::OutOfRange,
            "an under-allocated stream table must deny every StreamID"
        );
        assert!(bind(&mut words, log2, sid, bypass_ste()) == Err(StreamTableError::TableTooSmall));
    }

    /// **The decode seam, ∀ 2⁶⁴ entry words.** An STE permits *iff* it is valid (`V`) **and** its
    /// `Config[2]` is set — the architecture's own rule, stated as a biconditional so neither
    /// direction can rot: no invalid entry permits (isolation), and no valid non-abort entry is
    /// spuriously denied (which would make the through-STE control impossible and the deny vacuous).
    ///
    /// This runs over every word value, not just the two the constructors emit, so it covers entries
    /// the SMMU might see from memory this hypervisor did not write — the exact case a table built
    /// from stale or corrupt storage presents.
    #[kani::proof]
    fn an_ste_permits_iff_valid_and_not_configured_to_abort() {
        let word0: u64 = kani::any();
        let valid = word0 & 1 != 0;
        let not_abort = word0 & (1 << 3) != 0;
        assert!(
            decode(word0).permits() == (valid && not_abort),
            "an STE permits exactly when V is set and Config[2] is set"
        );
    }

    /// **The emit seam meets the decode seam.** The two constructors decode to exactly the verdicts
    /// their names claim. Kept as a proof rather than a unit test because it is the joint the whole
    /// rung hangs on: `deny_ste` is what the fail-closed default *is*, and `bypass_ste` is what makes
    /// the positive control a control. Written against `decode`, which is derived from the field
    /// definitions and not from the constructors (design-lesson #36).
    #[kani::proof]
    fn the_constructors_decode_to_their_names() {
        assert!(decode(deny_ste()[0]) == StreamVerdict::Invalid);
        assert!(!decode(deny_ste()[0]).permits());
        assert!(decode(bypass_ste()[0]) == StreamVerdict::Bypass);
        assert!(decode(bypass_ste()[0]).permits());
        // The bypass STE permits but confines nothing: it is a path witness, never an isolation
        // configuration. Pinned here so a later edit cannot quietly promote it to one.
        assert!(decode(bypass_ste()[0]).stage2_unconfined());
    }

    /// **The register encodings, ∀ size and ∀ address.** `STRTAB_BASE_CFG` announces the linear
    /// format and exactly the `log2size` the table was built for — a mismatch here is a table whose
    /// range check differs between the builder's belief and the hardware's, which is the
    /// configured-larger-than-allocated fail-open arriving by a different road. And `STRTAB_BASE`
    /// carries the address bits the field holds and nothing else, for every address.
    #[kani::proof]
    fn the_register_encodings_match_the_table_they_describe() {
        let log2: u32 = kani::any();
        match strtab_base_cfg(log2) {
            None => assert!(log2 > MAX_LOG2SIZE && table_words(log2).is_none()),
            Some(cfg) => {
                assert!(
                    cfg & 0x3f == log2,
                    "STRTAB_BASE_CFG.LOG2SIZE must be log2size"
                );
                assert!(
                    (cfg >> 16) & 0b11 == 0,
                    "STRTAB_BASE_CFG.FMT must be linear"
                );
                assert!(table_words(log2).is_some());
            }
        }

        let pa: u64 = kani::any();
        assert!(
            strtab_base(pa) == pa & 0x000f_ffff_ffff_ffc0,
            "STRTAB_BASE must carry exactly the ADDR field's bits"
        );
    }
}

/// **Stream → domain binding** — the SMMU arc, rung 3.
///
/// Rung 2 proved the stream table denies every StreamID nobody bound. It confines nothing: the entry
/// it binds is a *bypass* entry, and a bypassing device puts its own addresses straight on memory.
/// Rung 3 binds a stream to a **domain** instead — `STE.Config = 0b110`, `S2TTB` at the domain's own
/// `p2m`-derived Stage-2 tables, `S2VMID` the domain's VMID — and the property changes shape:
///
/// > ∀ StreamID: the memory a device reaches is exactly the memory the domain its STE names reaches.
///
/// **What carries over, and what does not.** The ∀-address refinement
/// (`stage2_leaf_authorized` / `encode_leaf_descriptors_follow_the_seam`) covers the device path
/// **verbatim and for free**, because it constrains the *table*, not the *walker* — a device walking
/// a domain's table is covered by construction. So this module deliberately does not re-prove any of
/// it. What nothing before rung 3 covers is the **binding** itself: that the entry for StreamID X
/// names domain D's table under D's VMID and nothing else. That is the exact analogue of the
/// `VTTBR_EL2` install, and its failure mode is not a fault but a *wrong domain's memory* — which is
/// why every refusal here is fail-closed and every field is proven to round-trip rather than merely
/// to fit.
///
/// **The regime harness is the one that would not have been written by looking at the code.** Two
/// walkers now read one table: the CPU under `VTCR_EL2`, the SMMU under the STE's own copy of the
/// same parameters. Under *different* parameters that is not a degraded translation but a different
/// one — a start level one off reads leaf descriptors as table descriptors. And the two encodings are
/// NOT the same field layout: `VTCR_EL2.TG0` and `STE.S2TG` order their granules differently, while
/// at baleen's 4 KiB granule both are `0b00` — a check whose two inputs are equal and so cannot
/// discriminate (design-lesson #71). The harness therefore ranges over every granule, and the
/// encoder's refusal to emit the ones whose `S2TG` encoding this crate has not verified is itself
/// part of what is proven.
///
/// **And what none of it proves:** that the SMMU reads those bits the way this crate writes them.
/// That arrow is the metal's, discharged by rung 3's two-sentinel positive control — the DMA landing
/// at the address the *table* names and not at the address the *device* named.
#[cfg(kani)]
mod smmu_stream_binding {
    use hv_s2::arm64::{
        decode_vtcr_el2, vtcr_el2, vttbr, vttbr_table, vttbr_vmid, Granule, PaSize, Stage2Regime,
        StartLevel, VmidBits, BALEEN_STAGE2, BALEEN_VMID_BITS,
    };
    use hv_s2::smmu::{
        bind_stage2, decode_stage2_binding, stage2_binding_at, stage2_ste, unbind, verdict,
        Stage2Binding, SteError, StreamTableError, StreamVerdict, STE_WORDS,
    };

    /// Four entries, as in the rung-2 module: the StreamID axis is what is symbolic here, the size
    /// axis is closed by the same means (the builder's size-generic refusals, plus the metal running
    /// `denies_every_stream` on the real 256-entry table every boot).
    const MAX_HARNESS_LOG2: u32 = 2;
    const WORDS: usize = (1 << MAX_HARNESS_LOG2) * STE_WORDS;

    fn any_log2() -> u32 {
        let n: u32 = kani::any();
        kani::assume(n <= MAX_HARNESS_LOG2);
        n
    }

    /// An arbitrary binding at the **deployed** regime: any table base the regime's alignment allows,
    /// any VMID it can express.
    fn any_binding() -> Stage2Binding {
        let s2ttb: u64 = kani::any();
        kani::assume(s2ttb >> 52 == 0);
        kani::assume(s2ttb % BALEEN_STAGE2.table_align() == 0);
        let vmid: u16 = kani::any();
        Stage2Binding {
            s2ttb,
            vmid,
            regime: BALEEN_STAGE2,
        }
    }

    /// An arbitrary translation regime — every granule, start level, output size and VMID width, and
    /// every input size a 6-bit `T0SZ` can name.
    fn any_regime() -> Stage2Regime {
        let g: u8 = kani::any();
        kani::assume(g < 3);
        let l: u8 = kani::any();
        kani::assume(l < 4);
        let p: u8 = kani::any();
        kani::assume(p < 7);
        let ipa_bits: u32 = kani::any();
        kani::assume(ipa_bits >= 16 && ipa_bits <= 64);
        let sh: u64 = kani::any();
        kani::assume(sh <= 0b11);
        let ir: u64 = kani::any();
        kani::assume(ir <= 0b11);
        let or: u64 = kani::any();
        kani::assume(or <= 0b11);
        Stage2Regime {
            granule: if g == 0 {
                Granule::K4
            } else if g == 1 {
                Granule::K16
            } else {
                Granule::K64
            },
            ipa_bits,
            start_level: if l == 0 {
                StartLevel::L0
            } else if l == 1 {
                StartLevel::L1
            } else if l == 2 {
                StartLevel::L2
            } else {
                StartLevel::L3
            },
            pa_size: if p == 0 {
                PaSize::B32
            } else if p == 1 {
                PaSize::B36
            } else if p == 2 {
                PaSize::B40
            } else if p == 3 {
                PaSize::B42
            } else if p == 4 {
                PaSize::B44
            } else if p == 5 {
                PaSize::B48
            } else {
                PaSize::B52
            },
            walk_shareability: sh,
            walk_inner: ir,
            walk_outer: or,
        }
    }

    /// **One regime, two walkers, ∀ regime.** Whenever the STE encoder emits an entry, the parameters
    /// the SMMU will walk under decode to exactly the parameters `VTCR_EL2` gives the CPU — same
    /// input size, same start level, same granule, same output size, same walk attributes.
    ///
    /// The non-vacuity half is the second assertion: the deployed regime really is encodable, so this
    /// is not a theorem about an empty set. And the refusal half is the `#71` guard — a granule whose
    /// `STE.S2TG` encoding is unverified is refused rather than encoded, so there is no regime for
    /// which the two walkers could silently differ.
    #[kani::proof]
    fn the_device_and_the_cpu_walk_under_one_regime() {
        let regime = any_regime();
        let width: bool = kani::any();
        let vmid_bits = if width { VmidBits::B8 } else { VmidBits::B16 };
        let b = Stage2Binding {
            s2ttb: 0,
            vmid: 0,
            regime,
        };
        match stage2_ste(&b) {
            Ok(ste) => {
                let device = decode_stage2_binding(&ste).expect("an emitted STE must decode");
                let cpu = vtcr_el2(&regime, vmid_bits).and_then(decode_vtcr_el2);
                assert!(
                    cpu == Some((device.regime, vmid_bits)),
                    "the SMMU's regime must be the CPU's regime"
                );
                assert!(
                    device.regime == regime,
                    "and both must be the one asked for"
                );
            }
            Err(SteError::BadRegime) => {
                assert!(!regime.valid() && vtcr_el2(&regime, vmid_bits).is_none())
            }
            Err(SteError::GranuleNotEmitted) => {
                // The only granules refused are the ones whose STE encoding is unverified — never
                // the deployed one.
                assert!(regime.granule != Granule::K4);
            }
            Err(_) => assert!(
                false,
                "a zero, aligned table base and VMID 0 refuse nothing else"
            ),
        }
        // Non-vacuity: the regime the metal actually runs passes both encoders.
        assert!(vtcr_el2(&BALEEN_STAGE2, BALEEN_VMID_BITS).is_some());
        assert!(stage2_ste(&Stage2Binding {
            s2ttb: 0,
            vmid: 0,
            regime: BALEEN_STAGE2
        })
        .is_ok());
    }

    /// **The `VTTBR_EL2` seam round-trips, ∀ table and ∀ VMID.** The metal derives the STE's `S2TTB`
    /// and `S2VMID` by reading them back out of the `VTTBR_EL2` value the domain's CPU would be
    /// given, which is how "the device walks the *same* table as the domain's CPU" holds by
    /// construction instead of by two derivations agreeing. If this seam lost a bit, the device would
    /// be bound to a table that is not the domain's.
    #[kani::proof]
    fn the_vttbr_seam_recovers_the_table_and_the_vmid() {
        let pa: u64 = kani::any();
        kani::assume(pa >> 48 == 0);
        let vmid: u64 = kani::any();
        kani::assume(vmid < 256);
        let v = vttbr(pa, vmid);
        assert!(vttbr_table(v) == pa);
        assert!(u64::from(vttbr_vmid(v, VmidBits::B8)) == vmid);
        // …and the masking is what keeps a VMID the CPU does not tag with off the device side: a
        // 16-bit value seen through an 8-bit regime yields the 8 bits the CPU actually uses.
        let wide: u64 = kani::any();
        kani::assume(wide < 65536);
        assert!(u64::from(vttbr_vmid(vttbr(pa, wide), VmidBits::B8)) == wide & 0xff);
        assert!(u64::from(vttbr_vmid(vttbr(pa, wide), VmidBits::B16)) == wide);
    }

    /// **A bound stream names exactly the domain it was given, ∀ table and ∀ VMID.** Every field
    /// round-trips through the independent decode seam — so no table base is truncated into a
    /// different table and no VMID is narrowed into another domain's.
    #[kani::proof]
    fn a_bound_stream_names_exactly_the_domain_it_was_given() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let sid: u32 = kani::any();
        kani::assume((sid as u64) < (1u64 << log2));
        let d = any_binding();

        assert!(bind_stage2(&mut words, log2, sid, &d).is_ok());
        assert!(stage2_binding_at(&words, log2, sid) == Some(d));
        // Translating, permitted — and NOT unconfined, which is the whole difference from rung 2.
        assert!(verdict(&words, log2, sid) == StreamVerdict::Stage2Only);
        assert!(verdict(&words, log2, sid).permits());
        assert!(!verdict(&words, log2, sid).stage2_unconfined());
    }

    /// **Binding a stream to a domain leaves every other stream denied, ∀ other StreamID.** The
    /// rung-2 property survives translation: giving one device access to one domain's memory gives no
    /// other device access to anything.
    #[kani::proof]
    fn binding_a_stream_to_a_domain_leaves_every_other_denied() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let bound: u32 = kani::any();
        kani::assume((bound as u64) < (1u64 << log2));
        assert!(bind_stage2(&mut words, log2, bound, &any_binding()).is_ok());

        let other: u32 = kani::any();
        kani::assume(other != bound);
        assert!(!verdict(&words, log2, other).permits());
        assert!(
            stage2_binding_at(&words, log2, other).is_none(),
            "no other stream may reach any domain's memory"
        );
    }

    /// **Rebinding replaces the domain completely, ∀ pair of domains.** The metal moves one device
    /// from one domain's tables to another's inside a single boot; a rebind that left any field of
    /// the previous binding behind would leave the device walking a mixture — the old table under the
    /// new VMID, say, which is a table nobody authorized.
    #[kani::proof]
    fn rebinding_a_stream_leaves_no_trace_of_the_previous_domain() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let sid: u32 = kani::any();
        kani::assume((sid as u64) < (1u64 << log2));

        let first = any_binding();
        let second = any_binding();
        assert!(bind_stage2(&mut words, log2, sid, &first).is_ok());
        assert!(bind_stage2(&mut words, log2, sid, &second).is_ok());
        assert!(stage2_binding_at(&words, log2, sid) == Some(second));
    }

    /// **`unbind` is still a true inverse, ∀ StreamID.** A domain binding is torn down to the same
    /// fail-closed default a bypass binding is — the state the whole table starts in.
    #[kani::proof]
    fn unbinding_a_domain_binding_restores_the_deny() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let sid: u32 = kani::any();
        kani::assume((sid as u64) < (1u64 << log2));
        assert!(bind_stage2(&mut words, log2, sid, &any_binding()).is_ok());
        assert!(unbind(&mut words, log2, sid).is_ok());

        let any: u32 = kani::any();
        assert!(!verdict(&words, log2, any).permits());
        assert!(stage2_binding_at(&words, log2, any).is_none());
    }

    /// **A binding that cannot be named exactly is refused, and writes nothing — ∀ table base and
    /// ∀ VMID.**
    ///
    /// This is the fail-closed half, and it is where the rung's failure mode is worst: `S2TTB` and
    /// `S2VMID` both silently drop bits if written oversized, and a truncated table pointer does not
    /// name a *smaller* permission — it names a **different domain's table**. So an address the field
    /// cannot carry exactly, or a VMID the CPU regime cannot express, must leave the entry denying
    /// rather than approximate it.
    #[kani::proof]
    fn a_binding_that_cannot_be_named_exactly_is_refused_and_writes_nothing() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let sid: u32 = kani::any();
        kani::assume((sid as u64) < (1u64 << log2));

        let s2ttb: u64 = kani::any();
        let vmid: u16 = kani::any();
        let d = Stage2Binding {
            s2ttb,
            vmid,
            regime: BALEEN_STAGE2,
        };
        let exact = s2ttb >> 52 == 0 && s2ttb % BALEEN_STAGE2.table_align() == 0;

        match bind_stage2(&mut words, log2, sid, &d) {
            Ok(()) => {
                assert!(exact, "only an exactly-nameable binding may be installed");
                assert!(stage2_binding_at(&words, log2, sid) == Some(d));
            }
            Err(StreamTableError::BadBinding(_)) => {
                assert!(!exact);
                let i: usize = kani::any();
                kani::assume(i < WORDS);
                assert!(words[i] == 0, "a refused binding must not write any word");
                assert!(!verdict(&words, log2, sid).permits());
            }
            Err(_) => assert!(false, "the StreamID is in range and the storage is sized"),
        }
    }

    /// **Nothing decodes as a domain binding unless it really is a stage-2 STE, ∀ 8 arbitrary
    /// words.** The stream table is memory, and the case a fail-closed reading must cover is memory
    /// this hypervisor did not write: a stale entry, a corrupt one, one left by firmware. A reader
    /// that answered "this stream reaches domain D" for such an entry would be inventing an
    /// authorization.
    #[kani::proof]
    fn no_entry_decodes_as_a_binding_unless_it_is_a_stage2_ste() {
        let ste: [u64; STE_WORDS] = kani::any();
        if let Some(b) = decode_stage2_binding(&ste) {
            assert!(hv_s2::smmu::decode(ste[0]) == StreamVerdict::Stage2Only);
            assert!(b.regime.valid());
            assert!(b.s2ttb >> 52 == 0);
        }
    }
}
/// **SMMU rung 4a — device assignment.** The ∀-value half of the device axis, on the shipped
/// [`hv_core::device`] code and the shipped [`Hypervisor`] seam.
///
/// What is proven here is exactly what the enumerator cannot reach. `hv-sim`'s ∀-N sweep visits
/// every state *reachable by a transition sequence* in one tiny config; these harnesses make the
/// **whole assignment vector symbolic** and prove the transitions total, non-destructive and
/// exactly-scoped over every vector at once — including the ones a short trace would take many
/// steps to build. Bounded on the device *count* (the collection axis Kani must unwind), unbounded
/// on nothing else: the domain ids are symbolic over the configured range.
///
/// The seam harnesses at the end cover the two facts that are **policy rather than invariant** —
/// no self-assignment, and a release that reveals nothing to a stranger. Neither breaks any state
/// predicate if it regresses, so a proof is the only thing that would notice.
#[cfg(kani)]
mod device_assignment {
    use hv_core::device::{DeviceError, System};
    use hv_core::{HvCall, HvError, Hypervisor};

    /// Domains and devices in the harness universe. Two domains — enough for a controller and a
    /// controlled peer, and see [`two_domain_world`] for why not more; two devices, so "exactly one
    /// device moved" is a statement with content.
    const NDOM: usize = 2;
    const NDEV: usize = 2;

    /// A device system in an **arbitrary** state: each device independently unassigned or held by
    /// an arbitrary in-range domain.
    ///
    /// Built by real `assign` calls rather than by reaching into the struct, so the state space is
    /// exactly the reachable one and the harness cannot prove something about a state the code can
    /// never be in (design-lesson #13f). Every vector *is* reachable — from all-unassigned, one
    /// `assign` per held device — so nothing is lost by construction either.
    fn symbolic_system() -> System {
        let mut s = System::new(NDOM, NDEV);
        for dev in 0..NDEV as u16 {
            if kani::any::<bool>() {
                let to: u16 = kani::any();
                kani::assume((to as usize) < NDOM);
                assert!(s.assign(dev, to).is_ok());
            }
        }
        s
    }

    /// Read the whole relation out, so "unchanged" can be stated about all of it at once.
    fn snapshot(s: &System) -> [Option<u16>; NDEV] {
        let mut out = [None; NDEV];
        for (dev, slot) in out.iter_mut().enumerate() {
            *slot = s.holder_of(dev as u16);
        }
        out
    }

    /// **`assign` is total, and a refusal writes nothing** — ∀ prior assignment vector, ∀ device,
    /// ∀ assignee.
    ///
    /// Three arms, and the third is the one that matters: on `Busy` the relation must be
    /// **bit-identical** to what it was. A refusal that re-pointed the device would not be a
    /// weaker permission — it would aim a live bus master at a different domain's memory with the
    /// previous holder never told (the same shape as `stage2_ste`'s refusal-not-truncation rule,
    /// design-lesson #73).
    #[kani::proof]
    #[kani::unwind(4)]
    fn assign_is_total_and_a_refusal_changes_nothing() {
        let mut s = symbolic_system();
        let before = snapshot(&s);

        let dev: u16 = kani::any();
        let to: u16 = kani::any();
        let r = s.assign(dev, to);
        let after = snapshot(&s);

        match r {
            Ok(()) => {
                assert!((dev as usize) < NDEV && (to as usize) < NDOM);
                assert!(after[dev as usize] == Some(to));
                // The prior holder was nobody or `to` itself — never a third domain silently
                // displaced.
                assert!(before[dev as usize].is_none() || before[dev as usize] == Some(to));
            }
            Err(DeviceError::Busy) => {
                assert!(before[dev as usize].is_some() && before[dev as usize] != Some(to));
                assert!(
                    after == before,
                    "a Busy refusal must not re-point the device"
                );
            }
            Err(DeviceError::BadDevice) => {
                assert!((dev as usize) >= NDEV);
                assert!(after == before);
            }
            Err(DeviceError::BadDomain) => {
                assert!((to as usize) >= NDOM);
                assert!(after == before);
            }
            Err(DeviceError::NotAssigned) => unreachable!("assign cannot report NotAssigned"),
        }
    }

    /// **An assignment moves exactly one device** — ∀ prior vector, ∀ (dev, to), every *other*
    /// device holds exactly what it held. The scoping half of the relation: assignment is
    /// per-device, never a mode the whole system enters.
    #[kani::proof]
    #[kani::unwind(4)]
    fn an_assignment_moves_exactly_one_device() {
        let mut s = symbolic_system();
        let before = snapshot(&s);

        let dev: u16 = kani::any();
        let to: u16 = kani::any();
        let _ = s.assign(dev, to);
        let after = snapshot(&s);

        for other in 0..NDEV {
            if other != dev as usize {
                assert!(after[other] == before[other]);
            }
        }
    }

    /// **`release` is total, and only the named holder's device moves** — ∀ prior vector,
    /// ∀ (dev, from). A release naming the wrong holder is refused with the *same* error as one
    /// naming a free device, and both leave the relation untouched.
    #[kani::proof]
    #[kani::unwind(4)]
    fn release_is_total_and_only_moves_the_named_holders_device() {
        let mut s = symbolic_system();
        let before = snapshot(&s);

        let dev: u16 = kani::any();
        let from: u16 = kani::any();
        let r = s.release(dev, from);
        let after = snapshot(&s);

        match r {
            Ok(()) => {
                assert!(before[dev as usize] == Some(from));
                assert!(after[dev as usize].is_none());
            }
            Err(DeviceError::NotAssigned) => {
                assert!(before[dev as usize] != Some(from));
                assert!(after == before);
            }
            Err(DeviceError::BadDevice) => {
                assert!((dev as usize) >= NDEV);
                assert!(after == before);
            }
            Err(DeviceError::BadDomain) => {
                assert!((from as usize) >= NDOM);
                assert!(after == before);
            }
            Err(DeviceError::Busy) => unreachable!("release cannot report Busy"),
        }
        for other in 0..NDEV {
            if other != dev as usize {
                assert!(after[other] == before[other]);
            }
        }
    }

    /// **The teardown sweep is exact** — ∀ prior assignment vector, ∀ holder:
    /// [`System::release_all_of`] leaves **no** device naming that holder, and leaves **every**
    /// device held by anyone else exactly where it was.
    ///
    /// Both halves are load-bearing and they fail in opposite directions. Too little and a bus
    /// master outlives its holder into a reborn slot (the confused deputy this rung exists to
    /// close); too much and destroying one domain silently disarms every other domain's devices —
    /// a denial of service that no invariant would flag, because an under-assigned relation
    /// violates nothing.
    #[kani::proof]
    #[kani::unwind(4)]
    fn the_sweep_takes_exactly_the_holders_devices() {
        let mut s = symbolic_system();
        let before = snapshot(&s);

        let holder: u16 = kani::any();
        kani::assume((holder as usize) < NDOM);
        s.release_all_of(holder);
        let after = snapshot(&s);

        assert!(!s.any_device_of(holder));
        for dev in 0..NDEV {
            if before[dev] == Some(holder) {
                assert!(after[dev].is_none());
            } else {
                assert!(
                    after[dev] == before[dev],
                    "the sweep took someone else's device"
                );
            }
        }
    }

    /// A two-domain world: dom0 creates and therefore controls dom1.
    ///
    /// **Two, not three, and the size is a measured constraint rather than a preference.** Every
    /// `dispatch` runs `first_cross_violation` under its `debug_assert`, an O(domains²) scan with a
    /// provenance walk inside it; at three domains the two seam harnesses below did not converge in
    /// **40 minutes**, against a 30-minute CI budget for the whole Kani suite. At two they are
    /// seconds. Nothing is lost that the other layers do not cover better: the ∀-domain content
    /// belongs to Verus (`device_assignment_preservation.rs`, arbitrary domain count) and to the
    /// enumerator (every reachable state of a three-domain config), while what only Kani can give
    /// — driving the **shipped** `dispatch` seam over symbolic inputs — needs just enough domains
    /// to have a controller and a controlled peer.
    fn two_domain_world() -> Hypervisor {
        let mut hv = Hypervisor::new(NDOM, 1, 1, 1, 1, 1, NDEV);
        assert!(hv
            .dispatch(
                0,
                HvCall::DomainCreate {
                    target: 1,
                    may_create: false
                }
            )
            .is_ok());
        hv
    }

    /// **No domain can assign itself a device — for every domain, and every device.**
    ///
    /// The one whole-domain operation with no `caller == target` exemption. This is proven rather
    /// than merely unit-tested because a self-assigned device is a **perfectly well-formed state**:
    /// it breaks no invariant, so if the gate regressed, every state predicate in the repository
    /// would stay green and only an explicit check would notice.
    ///
    /// Both domains are covered by the symbolic caller, and they fail the gate for different
    /// reasons — nobody controls dom0 at all, while dom1 *is* controlled, but by dom0, and
    /// `controls[1][1]` is the permanently-empty diagonal.
    #[kani::proof]
    #[kani::unwind(4)]
    fn no_domain_can_assign_itself_a_device() {
        let mut hv = two_domain_world();

        let caller: u16 = kani::any();
        kani::assume((caller as usize) < NDOM);
        let dev: u16 = kani::any();
        kani::assume((dev as usize) < NDEV);

        assert!(
            hv.dispatch(caller, HvCall::DeviceAssign { dev, to: caller }) == Err(HvError::Denied)
        );
        assert!(hv.device().holder_of(dev).is_none());
    }

    /// **Teardown leaves no device naming the destroyed domain, whatever it held** — ∀ device,
    /// driven through the real `dispatch` seam.
    ///
    /// The `first_cross_violation` assertion is the one that generalizes: it is the standing
    /// `DeadDomainReferenced` predicate, which since this rung reads the assignment relation, so a
    /// sweep that missed a device is caught as an invariant breach and not merely as a surprising
    /// query result.
    ///
    /// The **target is concrete** here (dom1 is the only creatable slot in a two-domain world) —
    /// see [`two_domain_world`] for why the world is that size. The ∀-target statement is Verus's
    /// (`destroy_preserves`, arbitrary domain count) and the enumerator's; what this adds is that
    /// the *shipped* teardown really does it.
    #[kani::proof]
    #[kani::unwind(4)]
    fn destroying_a_domain_leaves_no_device_naming_it() {
        let mut hv = two_domain_world();

        let dev: u16 = kani::any();
        kani::assume((dev as usize) < NDEV);

        assert!(hv.dispatch(0, HvCall::DeviceAssign { dev, to: 1 }).is_ok());
        assert!(hv.device().holder_of(dev) == Some(1));

        assert!(hv
            .dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 })
            .is_ok());

        assert!(hv.device().holder_of(dev) != Some(1));
        assert!(
            hv.first_cross_violation().is_none(),
            "a destroyed domain was left with a device assigned to it"
        );
    }
}

/// **SMMU rung 4b — the stream table is DERIVED from the assignment relation.**
///
/// Rung 4a put the device→domain relation in `hv-core` and proved it; rung 3 bound one stream to
/// one domain by hand. Nothing joined them, so the hardware's answer to *"whose memory may this bus
/// master write?"* was still a configuration nothing checked against the relation. `hv_s2::smmu::
/// derive_stream_table` is the join, and it is the device-axis twin of `build_stage2_from_p2m`.
///
/// **The theorem is a biconditional, and that is the whole point of the rung.**
///
/// > ∀ StreamID: the table binds it **iff** an assigned device carries it, to exactly that domain.
///
/// A one-directional theorem would have been the weaker rung, because the two directions fail
/// differently and neither implies the other. *Soundness* (⇐) is rung 2's ∀-StreamID default-deny
/// surviving derivation — losing it puts a device in some domain's memory with nothing to authorize
/// it. *Completeness* (⇒) is that every assignment is realized — losing it makes the proven relation
/// a decoration, satisfied by a derivation that writes nothing at all, which is exactly the shape ⑦
/// found in the Verus `Obs` split and rung 2's `binding_one_stream_…` non-vacuity clause guards.
///
/// **Three seams, not two.** `derive_stream_table` writes, `stage2_binding_at` reads the bytes back
/// through the architecture's field definitions, and `intended_binding` says independently what the
/// relation asks for. The assertions relate the second and the third, so a wrong emission and a
/// wrong expectation cannot agree (design-lesson #36).
///
/// **Sized to two devices and two domains, deliberately.** These are *pure builder* harnesses — no
/// `dispatch` seam, so none of `first_cross_violation`'s O(domains²) cost (design-lesson #79's
/// corollary) — but the device count is the axis Kani unwinds, and two is where every property here
/// has content: aliasing needs a pair, "one holder swept, another spared" needs a pair, and the
/// metal drives exactly one bus master. `hv_s2::smmu::MAX_PROVEN_DEVICES` is the shared constant
/// `hv-metal` pins its `NUM_DEVICES` against, so a device population proven here but not shipped —
/// or shipped but not proven — is a build error (design-lesson #71(c)).
#[cfg(kani)]
mod smmu_stream_derivation {
    use hv_core::device::System as DeviceSystem;
    use hv_s2::arm64::BALEEN_STAGE2;
    use hv_s2::smmu::{
        bind, bypass_ste, derive_stream_table, intended_binding, stage2_binding_at,
        table_refines_the_relation, verdict, DeriveError, Stage2Binding, MAX_PROVEN_DEVICES,
        STE_WORDS,
    };

    const NDOM: usize = 2;
    const NDEV: usize = MAX_PROVEN_DEVICES;

    /// Four entries — the StreamID axis is symbolic, and the *size* axis is closed the way rung 2
    /// closed it: the builder's refusals are size-generic, one harness below runs at the deployed
    /// 256-entry size, and the metal re-checks the real table every derivation.
    const MAX_HARNESS_LOG2: u32 = 2;
    const WORDS: usize = (1 << MAX_HARNESS_LOG2) * STE_WORDS;

    fn any_log2() -> u32 {
        let n: u32 = kani::any();
        kani::assume(n <= MAX_HARNESS_LOG2);
        n
    }

    /// A device system in an **arbitrary** state, built by real `assign` calls so the vector is a
    /// reachable one (the rung-4a idiom, design-lesson #13f).
    fn symbolic_devices() -> DeviceSystem {
        let mut s = DeviceSystem::new(NDOM, NDEV);
        for dev in 0..NDEV as u16 {
            if kani::any::<bool>() {
                let to: u16 = kani::any();
                kani::assume((to as usize) < NDOM);
                assert!(s.assign(dev, to).is_ok());
            }
        }
        s
    }

    /// An arbitrary binding at the deployed regime — any table base the alignment allows, any VMID.
    fn any_binding() -> Stage2Binding {
        let s2ttb: u64 = kani::any();
        kani::assume(s2ttb >> 52 == 0);
        kani::assume(s2ttb % BALEEN_STAGE2.table_align() == 0);
        let vmid: u16 = kani::any();
        Stage2Binding {
            s2ttb,
            vmid,
            regime: BALEEN_STAGE2,
        }
    }

    /// A `DomId → Stage2Binding` map in which every domain independently does or does not have
    /// emitted Stage-2 tables.
    fn symbolic_bindings() -> [Option<Stage2Binding>; NDOM] {
        let mut out = [None; NDOM];
        for slot in out.iter_mut() {
            if kani::any::<bool>() {
                *slot = Some(any_binding());
            }
        }
        out
    }

    /// The `DevId → StreamID` map the harnesses below derive from: two distinct in-range
    /// StreamIDs, with two more (1 and 3) that **no** device carries, so the denial arm has content.
    ///
    /// **Concrete on purpose, and the reason is measured.** A StreamID is an arbitrary label — the
    /// quantification that carries this rung's meaning is over the **query** (∀ StreamID, what does
    /// the table say?) and over the **assignment vector**, both of which stay symbolic. A symbolic
    /// *map* instead makes `bind_stage2` write at a symbolic offset, which is the single most
    /// expensive thing CBMC can be asked to do here: it took the biconditional from 21 s to 81 s and
    /// the two-derivation harnesses past ten minutes, against a whole-suite CI budget of forty-five.
    /// The one property that genuinely needs a symbolic map is the aliasing refusal, and that
    /// harness uses one. Injectivity itself is asserted rather than assumed, so this constant cannot
    /// quietly stop satisfying the builder's premise.
    const STREAMS: [u32; NDEV] = [0, 2];
    const _: () = assert!(STREAMS[0] != STREAMS[1]);
    const _: () = assert!((STREAMS[0] as u64) < (1 << MAX_HARNESS_LOG2));
    const _: () = assert!((STREAMS[1] as u64) < (1 << MAX_HARNESS_LOG2));

    /// **THE RUNG'S THEOREM, ∀ StreamID and ∀ assignment vector.** Whenever the derivation succeeds,
    /// the entry for every StreamID the table covers is *exactly* what the relation asks for — both
    /// directions in one statement, because the equality's `None` arm is the deny half and its
    /// `Some` arm is the realize half.
    ///
    /// The `permits` clause is not redundant with the binding equality, and the difference is the
    /// one rung 2 named: an entry can permit a device **unconfined** (a bypass STE) while decoding
    /// to no stage-2 binding at all, so `stage2_binding_at(..) == None` alone would call that table
    /// a faithful derivation of "nothing is assigned".
    #[kani::proof]
    fn the_derived_table_binds_exactly_the_assigned_streams() {
        let mut words = [0u64; WORDS];
        let log2 = MAX_HARNESS_LOG2;
        let devices = symbolic_devices();
        let streams = STREAMS;
        let bindings = symbolic_bindings();

        if derive_stream_table(&mut words, log2, &devices, &streams, &bindings).is_ok() {
            let sid: u32 = kani::any();
            let want = intended_binding(&devices, &streams, &bindings, sid);
            if (sid as u64) < (1u64 << log2) {
                assert!(
                    stage2_binding_at(&words, log2, sid) == want,
                    "the table must bind exactly the streams the relation assigns, to exactly those domains"
                );
                assert!(
                    verdict(&words, log2, sid).permits() == want.is_some(),
                    "and it must permit exactly those streams — nothing unconfined"
                );
            } else {
                assert!(!verdict(&words, log2, sid).permits());
            }
        }
    }

    // **There is deliberately NO deployed-size (256-entry) harness here, and the reason is measured
    // rather than assumed** — recorded because a silently-dropped axis reads as covered.
    //
    // Rung 2 has one (`the_deployed_stream_table_denies_every_streamid`) and it is cheap, because
    // `verdict` decodes a single word. A *derivation* harness at that size is not: it fills the
    // table, writes an STE, and then decodes three words at a symbolic StreamID out of a 2048-word
    // array. Measured on this machine: **265 s at 64 entries**, and non-terminating at ten minutes
    // at 256 — against a whole-suite CI budget of forty-five minutes, most of which is already
    // spent. The lever is harness world size, not the timeout (design-lesson #79's corollary).
    //
    // What covers the size axis instead, and it is not nothing:
    //   * the builder is **size-generic** — every write routes through `bind_stage2` → `bind` →
    //     `entry_offset`, whose size handling rung 2 proves over every size its storage supports
    //     *and* at `BUS0_LOG2SIZE` for the deny property;
    //   * `hv-s2`'s own unit tests run `derive_stream_table` at **`BUS0_LOG2SIZE`** — concretely,
    //     but at exactly the deployed size, including the sweep and every refusal arm;
    //   * `hv-metal` runs `table_refines_the_relation` over the **real 256-entry table** after every
    //     derivation and halts if it disagrees, so each boot is a ∀-StreamID check at the deployed
    //     size on the bytes the SMMU actually walks;
    //   * `STRTAB_LOG2SIZE = hv_s2::smmu::BUS0_LOG2SIZE` plus `const _` assertions in `hv-metal`
    //     make "proven at a size that is not shipped" a build error (design-lesson #71(c)).

    /// **A swept holder reaches nothing — the model's teardown, realized in the hardware table.**
    ///
    /// This is the rung's isolation content in proof form, and the model half of its headline probe:
    /// `release_all_of` is the *only* mechanism, so a derivation that ignored it would be caught
    /// here. Both halves of the sweep are asserted, because they are caught by different things
    /// (design-lesson #79): every stream of the dying holder's devices denies, **and** every other
    /// holder's device keeps exactly the binding it had — an over-sweep leaves every invariant in
    /// the repository perfectly satisfied while silently disarming the survivors.
    #[kani::proof]
    fn a_swept_holder_leaves_no_stream_bound_and_spares_the_others() {
        let mut words = [0u64; WORDS];
        let log2 = MAX_HARNESS_LOG2;
        let mut devices = symbolic_devices();
        let streams = STREAMS;
        let bindings = symbolic_bindings();
        kani::assume(derive_stream_table(&mut words, log2, &devices, &streams, &bindings).is_ok());

        let dying: u16 = kani::any();
        kani::assume((dying as usize) < NDOM);
        let held_before: [Option<u16>; NDEV] = [devices.holder_of(0), devices.holder_of(1)];

        devices.release_all_of(dying);
        let mut after = [0u64; WORDS];
        assert!(derive_stream_table(&mut after, log2, &devices, &streams, &bindings).is_ok());

        for dev in 0..NDEV {
            if held_before[dev] == Some(dying) {
                assert!(
                    !verdict(&after, log2, streams[dev]).permits(),
                    "a device of the destroyed domain still reaches memory after re-derivation"
                );
            } else {
                assert!(
                    stage2_binding_at(&after, log2, streams[dev])
                        == stage2_binding_at(&words, log2, streams[dev]),
                    "the sweep must not disarm another holder's device"
                );
            }
        }
    }

    /// **A refusal denies everything — ∀ input.** The derivation is total, and its failure mode is
    /// all-or-nothing: a table that bound the devices it *could* represent and quietly dropped the
    /// rest would be a configuration nothing describes.
    ///
    /// Nothing is assumed here — the StreamID map may alias, sit outside the table, or name a domain
    /// with no Stage-2 tables — so this is also the totality statement: every input reaches one of
    /// the two arms.
    #[kani::proof]
    fn a_refused_derivation_leaves_the_table_denying_every_stream() {
        let mut words = [0u64; WORDS];
        // Start from a table that already permits, so "denies everything" cannot pass by the storage
        // having been zero all along (design-lesson #66).
        let dirty: u32 = kani::any();
        kani::assume((dirty as u64) < (1u64 << MAX_HARNESS_LOG2));
        assert!(bind(&mut words, MAX_HARNESS_LOG2, dirty, bypass_ste()).is_ok());

        let log2 = any_log2();
        let devices = symbolic_devices();
        let streams: [u32; NDEV] = [kani::any(), kani::any()];
        let bindings = symbolic_bindings();

        if derive_stream_table(&mut words, log2, &devices, &streams, &bindings).is_err() {
            let sid: u32 = kani::any();
            assert!(
                !verdict(&words, log2, sid).permits(),
                "a refused derivation must leave nothing reachable"
            );
        }
    }

    /// **A map that aliases two devices onto one entry is refused** — the premise rung 4a's
    /// exclusivity rests on and does not itself establish.
    ///
    /// The model makes a second holder *unrepresentable* (`Option<DomId>`, not a set), which refines
    /// to exclusivity in the hardware only if `DevId → StreamID` is injective: two devices sharing a
    /// StreamID share one STE, so whichever is bound last decides where *both* land, and one
    /// domain's bus master silently walks another domain's tables. Unreachable at the metal's single
    /// device, which is exactly why it is proven rather than argued.
    #[kani::proof]
    fn a_map_that_aliases_two_devices_onto_one_entry_is_refused() {
        let mut words = [0u64; WORDS];
        let log2 = any_log2();
        let devices = symbolic_devices();
        let bindings = symbolic_bindings();

        let sid: u32 = kani::any();
        let streams = [sid, sid];

        assert!(
            derive_stream_table(&mut words, log2, &devices, &streams, &bindings)
                == Err(DeriveError::StreamAliased { a: 0, b: 1 })
        );
        let any_sid: u32 = kani::any();
        assert!(!verdict(&words, log2, any_sid).permits());
    }

    /// **The derivation is a function of the relation alone — ∀ prior table contents.**
    ///
    /// This is what makes "re-derive after every dispatch" sound rather than merely convenient: the
    /// table the metal publishes cannot carry residue from the state it was in before. Derived twice
    /// from the same relation — once over storage an adversary has scribbled a permissive entry
    /// into, once over zeroed storage — the words are **identical**, so a stream that stopped being
    /// assigned cannot survive as a stale entry the way a hand-maintained table could.
    #[kani::proof]
    fn the_derivation_is_a_function_of_the_relation_alone() {
        let log2 = MAX_HARNESS_LOG2;
        let devices = symbolic_devices();
        let streams = STREAMS;
        let bindings = symbolic_bindings();

        let mut dirty = [0u64; WORDS];
        let stale: u32 = kani::any();
        kani::assume((stale as u64) < (1u64 << MAX_HARNESS_LOG2));
        assert!(bind(&mut dirty, MAX_HARNESS_LOG2, stale, bypass_ste()).is_ok());
        let from_dirty = derive_stream_table(&mut dirty, log2, &devices, &streams, &bindings);

        let mut clean = [0u64; WORDS];
        let from_clean = derive_stream_table(&mut clean, log2, &devices, &streams, &bindings);

        assert!(from_dirty == from_clean);
        assert!(
            dirty == clean,
            "a re-derivation must leave no trace of the table's previous contents"
        );
    }

    /// **The check the metal runs on every derivation IS the property — and it can fail.**
    ///
    /// `table_refines_the_relation` is what the boot asserts over the real 256-entry table, so it
    /// has to be worth asserting: green whenever the derivation succeeded, and red for ∀ StreamID
    /// the relation does not authorize the moment that stream is permitted. Without the second half
    /// it would be a check that cannot fail, which reads as evidence when it is none (#71).
    #[kani::proof]
    fn the_refinement_check_is_the_property_and_can_fail() {
        let mut words = [0u64; WORDS];
        let log2 = MAX_HARNESS_LOG2;
        let devices = symbolic_devices();
        let streams = STREAMS;
        let bindings = symbolic_bindings();
        kani::assume(derive_stream_table(&mut words, log2, &devices, &streams, &bindings).is_ok());
        assert!(table_refines_the_relation(
            &words, log2, &devices, &streams, &bindings
        ));

        let sid: u32 = kani::any();
        kani::assume((sid as u64) < (1u64 << log2));
        kani::assume(intended_binding(&devices, &streams, &bindings, sid).is_none());
        assert!(bind(&mut words, log2, sid, bypass_ste()).is_ok());
        assert!(
            !table_refines_the_relation(&words, log2, &devices, &streams, &bindings),
            "permitting a stream the relation does not authorize must fail the check"
        );
    }
}

/// **The device-path composition** — the SMMU arc's headline sentence as one theorem rather than a
/// citation across three separately-proven links.
///
/// > A device assigned to `d` reaches exactly the frames `d`'s `p2m` authorizes, at exactly the
/// > emitter's permissions, and nothing else.
///
/// Rungs 1–4b each proved one link and none composed them, so the sentence above was carried by
/// prose — `docs/SMMU-TRANSLATION.md`'s "carries over verbatim", which is a citation doing the work
/// of a theorem (design-lesson #78). These harnesses drive the shipped path end to end: the model's
/// device relation → the derived stream table's **bytes** → the STE's decode seam → a **walk of the
/// emitted descriptor words** → the frame and permission `hv-core` authorized.
///
/// The two axes are priced separately and deliberately (design-lesson #79 — no silent caps):
/// [`the_walk_lands_where_the_windows_say`] and
/// [`a_device_reaches_exactly_the_memory_its_domain_reaches`] quantify over **every one of 2⁶⁴
/// addresses** with a bounded number of *mapped* frames, which is the direction that says nothing
/// else is reachable; [`a_device_never_reaches_an_unauthorized_frame`] quantifies over the **frame
/// index and the model's edge set**, which is the direction that says what is reachable is
/// authorized. Neither axis is dropped; they are carried by different harnesses because a symbolic
/// address and a symbolic edge population priced together do not terminate.
///
/// See `docs/SMMU-DEVICE-PATH-COMPOSITION.md`.
#[cfg(kani)]
mod device_path_composition {
    use hv_core::device::System as DeviceSystem;
    use hv_core::p2m::{DomId, Mfn};
    use hv_s2::arm64::{
        encode, frame_ipa, frame_pa, vttbr_table, vttbr_vmid, walk, window_reach, Layout, Reach,
        Tables, BALEEN_STAGE2, BALEEN_VMID_BITS, MAX_TABLE_PA, TABLE_ENTRIES,
    };
    use hv_s2::smmu::{
        derive_stream_table, device_reach, holder_of_stream, stage2_handles, HandleError,
        Stage2Binding, SteError, STE_WORDS,
    };
    use hv_s2::{leaf_map_from_edges, Maps, Perm};

    /// Domains, and therefore Stage-2 table **sets** — two, because the isolation content of the
    /// whole arc is "the *other* domain's memory", which needs a second set of tables to be wrong
    /// about.
    const NDOM: usize = 2;
    /// Devices. Two, as rung 4b: aliasing and "one holder swept, another spared" both need a pair.
    const NDEV: usize = 2;
    /// Base-span frames the harnesses make symbolic. The address axis stays fully symbolic, so the
    /// frames past this bound are covered in the direction that matters — their addresses are holes,
    /// and the theorem requires the walk to fault there.
    const SYM_BASE: usize = 3;
    /// The same for super-span frames.
    const SYM_SUP: usize = 2;
    /// A four-entry stream table, as rungs 3 and 4b: the StreamID axis is what is symbolic, and the
    /// size axis is closed by the builder's size-generic offset (rung 2, proven at the deployed
    /// `BUS0_LOG2SIZE` too) plus the metal's per-derivation read-back of the real 256-entry table.
    const LOG2: u32 = 2;
    const STRTAB_WORDS: usize = (1 << LOG2) * STE_WORDS;

    /// The `DevId → StreamID` map. Concrete for the reason rung 4b measured: a symbolic *map* makes
    /// the derivation write at a symbolic offset, which is the single most expensive thing CBMC can
    /// be asked to do here. The quantification that carries the meaning — ∀ StreamID *queried*, ∀
    /// assignment vector — stays symbolic.
    const STREAMS: [u32; NDEV] = [0, 2];

    /// Table storage for one domain's Stage-2 set, at PAs that differ per set exactly as
    /// `hv-metal`'s `STAGE2_SETS` do.
    struct Set {
        base: u64,
        /// Emit without the device pass-through window. Set only by the authorization harness,
        /// where the window costs sixteen `encode` iterations and bears on nothing the model says.
        no_device_window: bool,
        l1: [u64; TABLE_ENTRIES],
        l2_code: [u64; TABLE_ENTRIES],
        l2_data: [u64; TABLE_ENTRIES],
        l3_data: [u64; TABLE_ENTRIES],
        l2_sup: [u64; TABLE_ENTRIES],
        l2_dev: [u64; TABLE_ENTRIES],
    }

    impl Set {
        fn new(base: u64) -> Self {
            Set {
                base,
                no_device_window: false,
                l1: [0; TABLE_ENTRIES],
                l2_code: [0; TABLE_ENTRIES],
                l2_data: [0; TABLE_ENTRIES],
                l3_data: [0; TABLE_ENTRIES],
                l2_sup: [0; TABLE_ENTRIES],
                l2_dev: [0; TABLE_ENTRIES],
            }
        }

        fn layout(&self) -> Layout {
            Layout {
                l1_pa: self.base,
                l2_code_pa: self.base + 0x1000,
                l2_data_pa: self.base + 0x2000,
                l3_data_pa: self.base + 0x3000,
                l2_sup_pa: self.base + 0x4000,
                l2_dev_pa: self.base + 0x5000,
                // A fixture that populates every emitted region at once. Every domain is emitted at
                // the SAME guest IPA layout — what differs between two domains is which leaves are
                // mapped, which is exactly why "the wrong domain's tables" is a live hazard rather
                // than an obvious address mismatch.
                //
                // These numbers mirror NO shipped configuration, and the comment that used to call
                // them "the metal's synthetic windows" was wrong: the synthetic build emits
                // `device_len: 0` (no device window at all) and the real-Linux build emits a
                // 16 MiB one at `0x0800_0000` over a different RAM window entirely. Exercising a
                // combination no single config ships is the right thing here — the theorems these
                // harnesses carry quantify over the `Layout` (see the symbolic-layout harnesses
                // above, which take `device_base` from `bounded()`), so nothing rests on these
                // particular values. What must not happen is a reader taking them for deployed
                // ones; the deployed window is bound at run time by `hv-metal`'s `verify_encoding`
                // and asserted by `xtask::LINUX_MARKERS` in the `real-linux boot (QEMU)` job.
                guest_image_pa: Some(0x4020_0000),
                data_ipa_base: 0x8000_0000,
                data_pa_base: 0x4040_0000,
                frame_size: 0x1000,
                sup_ipa_base: 0xC000_0000,
                sup_pa_base: 0x4060_0000,
                sup_frames: SYM_SUP as u64,
                device_base: 0x0800_0000,
                device_len: if self.no_device_window {
                    0
                } else {
                    0x0200_0000
                },
                sup_wx_exempt: false,
            }
        }

        fn emit(&mut self, leaves: &[Option<Perm>], supers: &[Option<Perm>]) {
            let l = self.layout();
            encode(
                leaves,
                supers,
                &l,
                Tables {
                    l1: &mut self.l1,
                    l2_code: &mut self.l2_code,
                    l2_data: &mut self.l2_data,
                    l3_data: &mut self.l3_data,
                    l2_sup: &mut self.l2_sup,
                    l2_dev: &mut self.l2_dev,
                },
            );
        }

        /// One descriptor read out of this set, or `None` if the PA is not one of its tables.
        fn fetch(&self, table_pa: u64, index: u64) -> Option<u64> {
            let i = index as usize;
            match table_pa.checked_sub(self.base) {
                Some(0x0000) => Some(self.l1[i]),
                Some(0x1000) => Some(self.l2_code[i]),
                Some(0x2000) => Some(self.l2_data[i]),
                Some(0x3000) => Some(self.l3_data[i]),
                Some(0x4000) => Some(self.l2_sup[i]),
                Some(0x5000) => Some(self.l2_dev[i]),
                _ => None,
            }
        }
    }

    const SET0_PA: u64 = 0x4001_0000;
    const SET1_PA: u64 = 0x4002_0000;

    /// The whole machine's physical memory, as far as a walker is concerned: both domains' table
    /// sets. Anything else reads as zero — an invalid descriptor, hence a fault, which is the
    /// conservative answer and the one that makes a *missing* mapping visible as a disagreement.
    fn fetch(sets: &[Set; NDOM], table_pa: u64, index: u64) -> u64 {
        if let Some(w) = sets[0].fetch(table_pa, index) {
            return w;
        }
        if let Some(w) = sets[1].fetch(table_pa, index) {
            return w;
        }
        0
    }

    fn any_perm() -> Option<Perm> {
        let k: u8 = kani::any();
        kani::assume(k < 4);
        match k {
            0 => None,
            1 => Some(Perm::Ro),
            2 => Some(Perm::Rw),
            _ => Some(Perm::Rx),
        }
    }

    /// A device system in an arbitrary state, built by real `assign` calls so the vector is a
    /// reachable one (the rung-4a idiom, design-lesson #13f).
    fn symbolic_devices() -> DeviceSystem {
        let mut s = DeviceSystem::new(NDOM, NDEV);
        for dev in 0..NDEV as u16 {
            if kani::any::<bool>() {
                let to: u16 = kani::any();
                kani::assume((to as usize) < NDOM);
                assert!(s.assign(dev, to).is_ok());
            }
        }
        s
    }

    // ─── (1) the missing link: a walk of the words agrees with the layout, ∀ address ─────────────

    /// **∀ IPA: a walk of the descriptor words [`encode`] wrote lands exactly where the layout's
    /// windows say, or faults exactly where they say.**
    ///
    /// This is the link nothing had: `stage2_encoding` proves individual descriptors round-trip and
    /// `verify_encoding` checks the emitted table at boot *through the same derivation `encode`
    /// used*, so the step from "the leaf map says frame `m`" to "an address in frame `m`'s window
    /// arrives at frame `m`'s bytes" had never been written down, let alone proven.
    ///
    /// **It failed the first time it was run**, and the counterexample
    /// (`ipa = 0x0020_0000_C000_1007`) is now a comment in [`walk`]: every level indexes with nine
    /// bits, so an address beyond the tables' 512 GiB reach wrapped back into the super window and
    /// resolved to real memory. The walk `hv-metal` had used as its DMA-landing expectation since
    /// rung 3 had the same shape.
    #[kani::proof]
    fn the_walk_lands_where_the_windows_say() {
        let mut set = Set::new(SET0_PA);
        let l = set.layout();
        // Non-vacuity, and the premise the rest of the harness stands on: the deployed shape is one
        // the emitter accepts.
        assert!(l.validate().is_ok());

        let mut leaves = [None; SYM_BASE];
        for slot in leaves.iter_mut() {
            *slot = any_perm();
        }
        let mut supers = [None; SYM_SUP];
        for slot in supers.iter_mut() {
            *slot = any_perm();
        }
        set.emit(&leaves, &supers);

        let ipa: u64 = kani::any();
        let walked = walk(l.l1_pa, ipa, |pa, i| set.fetch(pa, i).unwrap_or(0));
        assert!(
            walked == window_reach(&l, &leaves, &supers, ipa),
            "a walk of the emitted words must land exactly where the layout says"
        );
    }

    // ─── (2) the join: one derivation of the table both consumers are pointed at ─────────────────

    /// **∀ table base and ∀ VMID: the CPU's `VTTBR_EL2` and the device's `S2TTB` name the table the
    /// emitter wrote into — or the handles are refused.**
    ///
    /// The premise `the_vttbr_seam_recovers_the_table_and_the_vmid` *assumes* (`pa >> 48 == 0`) is
    /// discharged here rather than assumed: above the field both registers truncate **identically**,
    /// so the two-walkers round-trip cannot see it, and both would walk a table `encode` never
    /// wrote. [`stage2_handles`] refuses instead, and `Layout::validate` refuses one rung earlier.
    #[kani::proof]
    fn the_two_consumers_are_pointed_at_one_table() {
        let l1_pa: u64 = kani::any();
        let vmid: u64 = kani::any();
        kani::assume(vmid < 256);
        let mut set = Set::new(SET0_PA);
        let mut l = set.layout();
        l.l1_pa = l1_pa;

        match stage2_handles(&l, vmid) {
            Ok(h) => {
                assert!(
                    h.binding.s2ttb == l.l1_pa,
                    "the device must be bound to the table the emitter was handed"
                );
                assert!(
                    vttbr_table(h.vttbr) == h.binding.s2ttb,
                    "and the CPU must be given the same one"
                );
                assert!(vttbr_vmid(h.vttbr, BALEEN_VMID_BITS) == h.binding.vmid);
                assert!(h.binding.regime == BALEEN_STAGE2);
            }
            Err(e) => {
                // The only refusals are bases one of the two registers cannot carry exactly —
                // never a truncation. The middle arm is the finding: `STE.S2TTB` is 52 bits and
                // `VTTBR_EL2.BADDR` is 48, so a base between them is nameable by one consumer and
                // not the other.
                assert!(matches!(
                    e,
                    HandleError::Ste(SteError::UnalignedTable)
                        | HandleError::Ste(SteError::TableAddressTooLarge)
                        | HandleError::VttbrNarrowerThanSte { .. }
                ));
                assert!(l1_pa >= MAX_TABLE_PA || l1_pa % BALEEN_STAGE2.table_align() != 0);
            }
        }
        // Non-vacuity: the shape the metal actually emits mints handles.
        assert!(stage2_handles(&set.layout(), 1).is_ok());
        let _ = set.fetch(0, 0);
    }

    // ─── (3) THE COMPOSITION, ∀ StreamID and ∀ address ───────────────────────────────────────────

    /// **THE RUNG'S THEOREM. ∀ StreamID and ∀ IPA: the memory a device reaches is exactly the memory
    /// the domain the model assigned it to reaches — and if the model assigned it to no one, none.**
    ///
    /// Every step is the shipped one and none is cited: the relation is `hv-core`'s, the table is
    /// [`derive_stream_table`]'s bytes, the STE is read back through the decode seam, and the
    /// address is resolved by **walking the descriptor words** the emitter wrote — through two
    /// domains' table sets at once, so "the wrong domain's memory" is a reachable outcome the
    /// theorem has to exclude rather than an unrepresentable one.
    #[kani::proof]
    fn a_device_reaches_exactly_the_memory_its_domain_reaches() {
        let mut sets = [Set::new(SET0_PA), Set::new(SET1_PA)];
        let mut leaves = [[None; SYM_BASE]; NDOM];
        let mut supers = [[None; SYM_SUP]; NDOM];
        let mut binding_of = [None; NDOM];

        for d in 0..NDOM {
            for slot in leaves[d].iter_mut() {
                *slot = any_perm();
            }
            for slot in supers[d].iter_mut() {
                *slot = any_perm();
            }
            let l = sets[d].layout();
            assert!(l.validate().is_ok());
            let leaf = leaves[d];
            let sup = supers[d];
            sets[d].emit(&leaf, &sup);
            // The metal registers a domain's binding from the emission itself, through the same
            // `Layout`. `vmid = d + 1` mirrors `hv-metal::stage2::set_vmid`.
            binding_of[d] = Some(
                stage2_handles(&l, d as u64 + 1)
                    .expect("deployed shape")
                    .binding,
            );
        }

        let devices = symbolic_devices();
        let mut strtab = [0u64; STRTAB_WORDS];
        kani::assume(
            derive_stream_table(&mut strtab, LOG2, &devices, &STREAMS, &binding_of).is_ok(),
        );

        let sid: u32 = kani::any();
        let ipa: u64 = kani::any();
        let reached = device_reach(&strtab, LOG2, sid, ipa, |pa, i| fetch(&sets, pa, i));

        let intended: Option<Reach> = match holder_of_stream(&devices, &STREAMS, sid) {
            Some(d) => window_reach(
                &sets[d as usize].layout(),
                &leaves[d as usize],
                &supers[d as usize],
                ipa,
            ),
            None => None,
        };
        assert!(
            reached == intended,
            "a device must reach exactly the memory of the domain the model assigned it to"
        );
    }

    // ─── (4) the other axis: what it reaches is AUTHORIZED ───────────────────────────────────────

    /// Frames in the symbolic model. Smaller than `stage2_refinement`'s world (4) and measured:
    /// the model axis and the descriptor-word axis priced together are what makes this the
    /// expensive harness, and three frames still express owner / grantee / third party.
    const FRAMES: usize = 3;
    /// Live page-table edges.
    const EDGES: usize = 2;

    fn auth_idx(grantor: DomId, grantee: DomId, frame: Mfn, writable: bool) -> u32 {
        (((grantor as u32 * NDOM as u32 + grantee as u32) * FRAMES as u32 + frame) * 2)
            + u32::from(writable)
    }

    /// **∀ StreamID, ∀ frame and ∀ model edge set: a device never reaches a frame its holder is not
    /// authorized for.** The arc's headline sentence, end to end and in the isolation direction —
    /// `hv-core`'s edges and grants at one end, the descriptor words a bus master walks at the other.
    ///
    /// The quantification is over the **frame index** rather than the whole address space, because
    /// the edge population and a symbolic address priced together do not terminate. The address axis
    /// is [`a_device_reaches_exactly_the_memory_its_domain_reaches`]'s, and it is the direction that
    /// says nothing *else* is reachable; this one says what is reachable is authorized. Declared
    /// rather than dropped (design-lesson #79).
    #[kani::proof]
    fn a_device_never_reaches_an_unauthorized_frame() {
        // The model world: ownership, grants, and an edge set — P1 and P2 assumed exactly as
        // `stage2_refinement` assumes them, because they are the same premises.
        let mut owners = [None; FRAMES];
        for slot in owners.iter_mut() {
            if kani::any::<bool>() {
                let d: DomId = kani::any();
                kani::assume((d as usize) < NDOM);
                *slot = Some(d);
            }
        }
        let auth: u128 = kani::any();
        let owner_of = |m: Mfn| -> Option<DomId> {
            if (m as usize) < FRAMES {
                owners[m as usize]
            } else {
                None
            }
        };
        let authorizes = |g: DomId, d: DomId, f: Mfn, w: bool| -> bool {
            auth & (1u128 << auth_idx(g, d, f, w)) != 0
        };
        let mut edges = [(0u32, 0u32, 0u32, false, false, false); EDGES];
        for e in edges.iter_mut() {
            let parent: Mfn = kani::any();
            let child: Mfn = kani::any();
            kani::assume((parent as usize) < FRAMES);
            kani::assume((child as usize) < FRAMES);
            *e = (parent, kani::any(), child, kani::any(), true, kani::any());
        }
        for (parent, _slot, child, writable, _leaf, _execute) in edges.iter().copied() {
            // P2: an active edge's child is allocated.
            kani::assume(owner_of(child).is_some());
            // P1: `UnauthorizedForeignLink`.
            if let (Some(co), Some(po)) = (owner_of(child), owner_of(parent)) {
                if co != po {
                    kani::assume(authorizes(co, po, child, writable));
                }
            }
        }

        // The emitted images: one per domain, from the model, through the shipped emitter.
        let mut sets = [Set::new(SET0_PA), Set::new(SET1_PA)];
        sets[0].no_device_window = true;
        sets[1].no_device_window = true;
        let mut leaves = [[None; FRAMES]; NDOM];
        let mut binding_of = [None; NDOM];
        for d in 0..NDOM {
            let mut sup = [None; SYM_SUP];
            let mut base = [None; FRAMES];
            let ok = leaf_map_from_edges(
                &edges,
                owner_of,
                |_p| Some(hv_s2::Span::Base),
                d as DomId,
                Maps {
                    base: &mut base,
                    sup: &mut sup,
                },
            )
            .is_ok();
            kani::assume(ok);
            leaves[d] = base;
            let l = sets[d].layout();
            sets[d].emit(&base, &sup);
            binding_of[d] = Some(
                stage2_handles(&l, d as u64 + 1)
                    .expect("deployed shape")
                    .binding,
            );
        }

        let devices = symbolic_devices();
        let mut strtab = [0u64; STRTAB_WORDS];
        kani::assume(
            derive_stream_table(&mut strtab, LOG2, &devices, &STREAMS, &binding_of).is_ok(),
        );

        let sid: u32 = kani::any();
        let m: Mfn = kani::any();
        kani::assume((m as usize) < FRAMES);
        let l = sets[0].layout();
        let ipa = frame_ipa(&l, m);

        if let Some(r) = device_reach(&strtab, LOG2, sid, ipa, |pa, i| fetch(&sets, pa, i)) {
            let d = holder_of_stream(&devices, &STREAMS, sid)
                .expect("an unassigned stream reaches nothing");
            assert!(
                r.pa == frame_pa(&l, m),
                "a device that reaches a frame's IPA must land on that frame's bytes"
            );
            // …and that frame is one the model authorizes for the domain the device belongs to,
            // **at the permission the device got**. Stated pointwise for the frame actually
            // reached rather than by calling `check_authorized_with` over the whole map: the
            // whole-map statement is `stage2_refinement`'s theorem over this very function, and
            // re-asserting it here would duplicate what a lower layer proves (design-lesson #80)
            // — while costing, measured, more than the rest of the harness put together.
            let owner = owner_of(m);
            assert!(
                owner == Some(d) || owner.is_some_and(|o| authorizes(o, d, m, r.writable())),
                "a bus master reached a frame its holder neither owns nor holds a grant for"
            );
            assert!(
                leaves[d as usize][m as usize].is_some(),
                "and it is a frame that domain's own leaf map maps"
            );
        }
    }

    // ─── (5) the clauses without which the four above are green over an empty set ────────────────

    /// **Non-vacuity, and it is the trap for a composition specifically.** Every theorem above is a
    /// biconditional or an implication, and all of them hold vacuously if no device ever reaches
    /// anything. So: at the deployed configuration, with one device assigned, there **exists** a
    /// StreamID and an address the device really does reach, at the permission the emitter emitted.
    #[kani::proof]
    fn the_composition_is_not_vacuous() {
        let mut sets = [Set::new(SET0_PA), Set::new(SET1_PA)];
        let leaves = [Some(Perm::Rw), Some(Perm::Ro), None];
        let supers = [None; SYM_SUP];
        let mut binding_of = [None; NDOM];
        for d in 0..NDOM {
            let l = sets[d].layout();
            sets[d].emit(&leaves, &supers);
            binding_of[d] = Some(
                stage2_handles(&l, d as u64 + 1)
                    .expect("deployed shape")
                    .binding,
            );
        }
        let mut devices = DeviceSystem::new(NDOM, NDEV);
        assert!(devices.assign(0, 1).is_ok());
        let mut strtab = [0u64; STRTAB_WORDS];
        assert!(derive_stream_table(&mut strtab, LOG2, &devices, &STREAMS, &binding_of).is_ok());

        let l = sets[1].layout();
        // The writable frame: reached, at the frame's own PA, read/write, execute-never.
        let r = device_reach(&strtab, LOG2, STREAMS[0], frame_ipa(&l, 0), |pa, i| {
            fetch(&sets, pa, i)
        });
        assert!(
            r == Some(Reach {
                pa: frame_pa(&l, 0),
                perm: Perm::Rw,
                xn: true
            }),
            "the assigned device must really reach its domain's writable frame"
        );
        // The read-only frame: reached, and NOT writable — the permission crosses the seam.
        let ro = device_reach(&strtab, LOG2, STREAMS[0], frame_ipa(&l, 1), |pa, i| {
            fetch(&sets, pa, i)
        });
        assert!(ro.map(|r| r.perm) == Some(Perm::Ro));
        // The unmapped frame: a hole.
        assert!(
            device_reach(&strtab, LOG2, STREAMS[0], frame_ipa(&l, 2), |pa, i| {
                fetch(&sets, pa, i)
            })
            .is_none()
        );
        // The other device's StreamID: assigned to no one, reaches nothing anywhere.
        assert!(
            device_reach(&strtab, LOG2, STREAMS[1], frame_ipa(&l, 0), |pa, i| {
                fetch(&sets, pa, i)
            })
            .is_none()
        );
    }

    /// **The theorem can fail, and the way it fails is the isolation content** (design-lesson #71 —
    /// a check that could not have failed reads as evidence when it is none). Bind the stream to the
    /// *other* domain's tables — one field of one entry — and the device lands on the wrong domain's
    /// memory at the same issued address, or on nothing at all.
    #[kani::proof]
    fn binding_the_wrong_domain_reaches_the_wrong_memory() {
        let mut sets = [Set::new(SET0_PA), Set::new(SET1_PA)];
        // Domain 0 maps frame 0; domain 1 does not map it at all.
        let a_leaves = [Some(Perm::Rw), None, None];
        let b_leaves = [None, Some(Perm::Rw), None];
        let supers = [None; SYM_SUP];
        sets[0].emit(&a_leaves, &supers);
        sets[1].emit(&b_leaves, &supers);
        let a: Stage2Binding = stage2_handles(&sets[0].layout(), 1)
            .expect("deployed")
            .binding;
        let b: Stage2Binding = stage2_handles(&sets[1].layout(), 2)
            .expect("deployed")
            .binding;
        assert!(a.s2ttb != b.s2ttb, "two sets must be two tables");

        let l = sets[0].layout();
        let ipa = frame_ipa(&l, 0);
        let mut right = [0u64; STRTAB_WORDS];
        let mut wrong = [0u64; STRTAB_WORDS];
        let mut devices = DeviceSystem::new(NDOM, NDEV);
        assert!(devices.assign(0, 0).is_ok());
        assert!(
            derive_stream_table(&mut right, LOG2, &devices, &STREAMS, &[Some(a), Some(b)]).is_ok()
        );
        // The same relation, derived against a binding map that names the wrong tables.
        assert!(
            derive_stream_table(&mut wrong, LOG2, &devices, &STREAMS, &[Some(b), Some(a)]).is_ok()
        );

        assert!(
            device_reach(&right, LOG2, STREAMS[0], ipa, |pa, i| fetch(&sets, pa, i))
                == Some(Reach {
                    pa: frame_pa(&l, 0),
                    perm: Perm::Rw,
                    xn: true
                })
        );
        assert!(
            device_reach(&wrong, LOG2, STREAMS[0], ipa, |pa, i| fetch(&sets, pa, i)).is_none(),
            "bound to the wrong domain's tables, the device must not reach its own domain's frame"
        );
    }
}
