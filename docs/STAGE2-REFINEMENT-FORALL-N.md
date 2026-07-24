<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# The Stage-2 refinement, ∀-N — "Tier C for the metal", Arc 3

Arc 1 factored the Stage-2 decision out of the `unsafe` metal into `hv-s2`. Arc 2 wrote its
guarantees as executable predicates and checked them over every reachable state. Arc 2.5 audited
the *statement* before proving it, and machine-checked the encoder hop. This arc lifts the one
predicate that is a genuine theorem — `check_authorized`, *no reachability without authorization* —
from "checked over every reachable state of small configs" to **∀-N**.

## 1. The theorem

> **T.** For every model state satisfying **(P1)** `UnauthorizedForeignLink` and **(P2)** every
> active edge's child is allocated, and every domain `G`: every frame the emitted Stage-2 leaf map
> reaches is one `G` **owns**, or one an **active grant** from its owner authorizes `G` for at the
> mapped permission.

Equivalently, and this is the sentence the project actually claims: **a frame `G` neither owns nor
holds a grant for is not in `G`'s page table at all** — the guest takes a translation fault rather
than reaching it. Both forms are proven (`an_unauthorized_frame_is_a_hole`,
`an_unauthorized_frame_is_never_mapped`), so the negative form is machine-checked and not left to a
reader's contraposition. So is the sharper permission half: a writable leaf is never backed by a
read-only grant.

### Why this needed deduction rather than a bigger sweep

Every other bounded axis in this program was closed by **saturation** (Tier B: run the BFS until
the frontier empties, and the depth bound dissolves). That route is unavailable here *by
construction*. Tier B proved grant+p2m **together** is the one config whose reachable set is
genuinely infinite — `grant::map` bumps a `u32` with no cap, so `maps`/`refs` climb forever and the
frontier can never empty. Arc 2's 828,325-state sweep is therefore not extensible into a theorem by
running it harder. Deduction is not a stylistic preference here; it is the only route.

## 2. The proof shape — where the strength comes from

Unfolded, T is short. `leaf_map` writes `out[m] = Some(π)` only from an edge
`(p, _, m, w, leaf=true)` with `owner_of(p) == Some(G)` and `π = w ? Rw : Ro`. So:

* **owner(m) == G** — ownership is the authorization. Done.
* **owner(m) == G' ≠ G** — the edge is cross-domain, and P1 applied *to that edge* yields
  `grant.authorizes(G', G, m, w)`. That is verbatim what `check_authorized` demands. The grantee
  lines up because hv-core's invariant uses `owner(parent)` as grantee, and the emitter only
  selected the edge because `owner(parent) == G`.
* **owner(m) == None** — excluded by P2. See §3.

The only ∀-N content is one loop invariant: *every `Some` slot in the output is witnessed by an
already-consumed edge*, over an unbounded edge population. Everything after it is per-frame case
analysis with no quantifier depth. That is why this obligation came in tractable rather than
heroic — the same cost finding Tier C and Tier D both recorded.

The overwrite semantics matter and are modelled: a later selected edge into the same frame replaces
an earlier one, so the witness must be **existential, not unique**. Both edges are individually
authorized by P1, so which one wins is immaterial to T.

## 3. The premises — and which one is load-bearing

**P1 (`UnauthorizedForeignLink`) is cited, not proven, and it is the weaker link.** It is checked by
the enumerator over every reachable state and carries a Tier-B locality cutoff
(`docs/TIER-B-CUTOFF.md` §2.2: 1 edge + 2 owners + 1 grant), but **no Verus proof discharges it** —
it is not a machine-checked ∀-N theorem. T composes with it; T does not prove it. Saying otherwise
would be exactly the overclaim class design-lesson #37 was written about — and an earlier revision
of `hv-s2/src/check.rs` did say "already-proven". That comment is corrected in this arc.

**P2 (every active edge's child is allocated) is a genuinely separate premise, not a consequence of
P1.** This surfaced only from writing the theorem out precisely. `UnauthorizedForeignLink`
*skips* an edge either of whose ends is unowned (`first_cross_violation`'s `else { continue }`),
while `check_authorized` *rejects* a mapped frame nobody owns. **Without P2, T is false at
`owner(m) == None`.** It holds because `p2m::link` refuses an unallocated child
(`hv-core/src/p2m.rs`) and the reference the edge takes on that child blocks a later free. That is
an argument, and it is stated as a premise rather than left implicit.

## 4. What T does NOT say

T is **soundness, not completeness**. It forbids reaching an unauthorized frame; it does not claim
every authorized frame is reachable. That asymmetry is what makes it true: the emitter maps only
leaves of tables the domain **owns**, so a legitimately shared **interior node** (the model permits
sharing a whole subtree) yields *no* mapping beneath it — an **under**-map, failing **closed**. A
completeness claim would simply be false. Also outside T, carried verbatim from `hv-s2`'s scope
boundaries: superpage size (a model leaf pins one `Mfn`), the guest-image block (infrastructure, not
model-driven; proven RO+X by Kani in Arc 2.5), `GuestMem` (the trusted path, unconditional on
`S2AP`), and VMID/table-set binding (lives in `hv-metal`).

## 5. What each tool closes — three complementary axes over one obligation

Neither tool alone is the theorem, and the split was chosen by what each can actually reach on the
**code that runs**.

| | object | edge count | values covered |
|---|---|---|---|
| `hv-sim` enumerator (Arc 2) | **real code**, real *reachable* states | small | 828,325 states, no violation |
| Kani `stage2_refinement` | **real, shipped** `leaf_map_from_edges` / `check_authorized_with` | bounded (3) | *every* ownership assignment, grant table, permission, capacity, domain |
| Verus `stage2_leaf_authorized.rs` | mirror (~20 lines) | **arbitrary** | arbitrary frame count, domain count, grant relation |

Kani cannot construct a symbolic `Hypervisor` — it is heap `Vec`s, and worse, an *arbitrary
reachable* one. So the emitter and the checker each grew an oracle-parameterised seam
(`leaf_map_from_edges`, `check_authorized_with`) that production calls through a two-line wrapper.
Production keeps **one** derivation (design-lesson #14c); the proof gets a handle on the shipped
function rather than a re-modelled copy.

**The honest ceiling:** nothing available proves ∀-N on the *literal* running code. Verus front-ends
whole crates and cannot be `#[cfg]`-hidden, so verifying `hv-s2` in place would break the stable
build every other crate depends on (design-lesson #21a) — `hv-s2` being small does not change that.
What T rests on is a ~20-line transcription whose *shape* is independently pinned on real code by
Kani over all values, and whose behaviour is pinned on real code by the enumerator over 828k
reachable states. That is a managed gap, not an eliminated one.

## 6. Non-vacuity (measured, not asserted)

Every mutation below was run; the tools **reject** — they do not merely fail a test.

| mutation | tool | object mutated | result |
|---|---|---|---|
| drop the `owner(parent) == dom` filter | Kani | **shipped `leafmap.rs`** | ✅ rejected — *"reached a frame no ownership or grant authorizes"* |
| map `Rw` regardless of the edge's permission | Kani | **shipped `leafmap.rs`** | ✅ rejected — *"a writable leaf must be owned or backed by a read-write grant"* |
| drop the `owner(parent) == dom` filter | Verus | mirror | ✅ rejected (6 verified, 1 error) |
| always-`Rw` | Verus | mirror | ✅ rejected (6 verified, 1 error) |
| drop premise P2 | Verus | mirror | ✅ rejected (6 verified, 1 error) |
| **drop the `leaf` filter** | Verus | mirror | ⚠️ **still verifies — and that is correct** |

The last row is the informative one and is recorded rather than buried. P1 authorizes *every*
cross-domain edge, interior ones included, so the leaf filter carries **no authorization content**.
Its content is exactness — an interior edge must map no frame — which is `check_exact`'s remit, and
`check_exact` is honestly labelled a **consistency check, not a theorem** (Arc 2). A mutation
harness that "caught" it would have been catching it for the wrong reason.

Likewise, the silent-under-map mutation (dropping Arc 1's fail-loud `FrameOutOfRange`) is **not**
caught by T, and should not be: under-mapping fails closed, which is precisely what §4 says T does
not cover. It is covered instead by `FrameOutOfRange` being an error the metal halts on, which the
Kani harness proves is the only alternative to an authorized map — "**fails loudly, or is
authorized**", with no third outcome.

## 7. Residual ledger

1. **P1 is not ∀-N — this is the top of the ledger, and it is Arc 3b.** Lifting
   `UnauthorizedForeignLink` to a Verus preservation proof (`p2m_link` establishes it; unlink, frame
   free, grant revoke, and `DomainDestroy` preserve it) is what would make T unconditional.
   Estimated ~5–8 lemmas, in line with the Tier C/D lemma counts.
2. **Mirror fidelity** for the ∀-length step — managed by layered anchors (§5), not eliminated.
3. **Arrows (2) and (3)** of the chain are Arc 2.5's and QEMU's, unchanged by this arc.
4. **Edge count in Kani is bounded at 3** — deliberately, since Verus lifts exactly that axis. The
   bound is stated in the harness, not silently chosen.

## 8. Running it

```sh
cargo kani -p hv-verify                                     # 13 harnesses, incl. stage2_refinement
verus --crate-type=lib hv-verify/verus/stage2_leaf_authorized.rs   # → 7 verified, 0 errors
```

Both run in CI's `deep-verify.yml` (the Kani job runs the whole crate; the Verus job loops over
every `hv-verify/verus/*.rs`), so neither needed a workflow change to pick this arc up.
