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
