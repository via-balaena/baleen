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
