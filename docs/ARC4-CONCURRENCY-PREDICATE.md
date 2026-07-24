# M5 Arc 4 — the concurrency predicate, made checkable

**Status:** done. `hv-core` / `hv-hal` / `hv-s2` untouched.

Nine `unsafe impl Sync` in `hv-metal` were justified by one commented predicate —
*"single boot CPU; secondaries stay PSCI-parked in `_start`"* — and every outward direction (SMP,
more guests, real hardware, x86) breaks it. The worry was that when it breaks, nine `unsafe` blocks
stop being sound **at once and silently**.

Following design-lessons #37 (audit the statement before you prove it) and #39 (delete each
hypothesis and see which ones fire), this arc classified the nine sites **before** proposing any
mechanism. The classification inverted the framing.

---

## 1. The audit: it was never one predicate

| # | Site (pre-arc) | The obligation it actually carries | Where it is enforced |
|---|---|---|---|
| 1 | `heap.rs:58` `Arena` | **none beyond the atomic.** Disjointness comes from the `compare_exchange` on a monotonic offset | already sound at any CPU count |
| 2 | `stage2.rs:161` `Table` | **publication** to a non-CPU agent (the Stage-2 walker + VMID-tagged TLB). Rebuilt per phase and per rebirth, so *not* write-once | `enable_stage2`'s `dsb`+`tlbi`+`isb`, the rebirth flush (#28f) |
| 3 | `linux.rs:110` `Table` | same, strict write-once-before-enable | as above |
| 4 | `guest.rs:1695` `MetaCell` | **publication between phases** — written at setup, read out **by value**, so no reference escaped | already the right shape |
| 5–9 | `guest.rs:1391/1399/1413/1429/1662` `HvCell`, `VirtioCell`, `BlkCell`, `BlkDiskCell`, `CtxCell` | **exclusive `&mut` / non-reentrancy** — a *single-CPU* property | **prose only** |

Three distinct properties, not one:

1. **No second CPU executes hypervisor code.**
2. **No agent observes a half-built structure.**
3. **No two mutable borrows of one cell are live at once.**

A single lock would have been the wrong shape for six of the nine sites.

### The inversion

**Class 1 — the predicate every comment cited — was already machine-enforced, and not by PSCI.**
`main.rs:77-79` masks `MPIDR_EL1[23:0]` and hard-parks any core with nonzero affinity *before the
boot stack is set*. The SAFETY comments cited PSCI parking and thereby **under-claimed what the code
already does**.

**Class 3 — never named in any comment — is the load-bearing one.** Four accessors handed out
`&'static mut` with no lifetime tie (`virtio_dev`, `blk_dev`, `blk_disk`, `sched_hv`), so nothing at
any level prevented two live aliases to one cell.

**And class 3 does not break because of SMP.** `handle_guest_irq` (`guest.rs:1839`) touches no cell
today — only GIC MMIO and atomics. But `VcpuOps::inject_interrupt` is unrealized and sits in the
deferral ledger; realizing it puts an asynchronous EL2 handler onto `hv-core` state, which is a
second agent **on one CPU**. `IN_GUEST_HANDLER` guards sync-vs-sync handler nesting; nothing guarded
IRQ-vs-sync, and nothing guarded setup-vs-handler.

---

## 2. The mechanism

`hv-metal/src/cell.rs` — **one** cell type, **one** `Sync` argument, a **runtime claim**, and a
**bounded guard lifetime**.

- `BootCell<T>::borrow_mut()` takes a per-cell claim by `compare_exchange` and returns a `BootRef<T>`
  guard; `BootRef`'s `Drop` is the sole release; a second claim **halts loudly**.
- The compile-time half does most of the work: a `&mut T` derived from a `BootRef` is bounded by the
  guard, so the borrow checker rejects statically what the old `&'static mut` left to a comment.
- `assert_boot_cpu` re-states class 1 on the **executing** path (`_start` covers only the entry path).
- `BootCell::as_ptr` is the one documented hole: it does **not** claim, and its two callers hand a
  pointer to the guest-entry trampoline and then `eret` out of EL2 — there is no borrow to hold, and
  a claim taken there could never be released.

### What the shape bought

Putting **one cell over a whole table set** (rather than one per table) means the four tables come
out as **disjoint field borrows the compiler checks**. So the Stage-2 emitter and the real-Linux
table build dropped to **zero `unsafe`** — the aliasing half of their old SAFETY blocks is now a
type-system fact, and what remains in prose is only the publication (barrier) argument, which lives
with the barriers where it belongs.

| | before | after |
|---|---|---|
| `unsafe impl Sync` in hv-metal | 9 | **2** (`BootCell` + `Arena`) |
| `unsafe` constructs (`unsafe {` / `impl` / `fn`) | 105 | **70** |
| `stage2.rs` | 5 | **2** (both in `GuestMem`, none in Stage-2 emission) |
| `guest.rs` | 67 | **30** |
| boot-test checks | 130 | **131** |

`heap.rs`'s `Arena` deliberately stays **out** of `BootCell`, and had its single-CPU hypothesis
**deleted**: the CAS carries the whole argument, so the arena is soundly *shared*, not exclusive.
Forcing it into the exclusive box would have asserted a property it does not need and does not have.

---

## 3. The mechanism found two real overlaps on its first boot

Both are exactly the shape named in the design call — a `&'static mut` that stays nominally live
across a divergence, sound only because nothing uses it afterwards, with nothing checking that.

1. **Every phase-setup function held its model claim across the `eret` into the guest.** The first
   boot halted at the very first trap. Fixed by releasing at the seam: entering the guest is where
   EL2 relinquishes its state (nine sites).
2. **`finish_virtio_blk_test` held a `&'static mut BlkDisk` across a divergent tail call** into
   `begin_gic_phase`, so it was *still in scope* four phases later when the thesis phase minted a
   second one. This is a genuine overlapping `&mut` under the pre-arc code. Fixed by scoping.

---

## 4. Non-vacuity, and the hypotheses that do **not** fire

Every row was run: patch, boot under QEMU, record, revert.

| # | Mutation | Result |
|---|---|---|
| 1 | Delete the exclusion flag (`try_claim` always succeeds) | **FAILS** — `BootCell exclusion FAIL (refused=false regained=true hv_refused=false hv_regained=true)`. A degenerate always-open flag cannot print the marker. |
| 2 | Delete `assert_boot_cpu` from `borrow_mut` | **STILL GREEN — does not fire.** Recorded, not hidden. |
| 3 | `Drop` no longer releases the claim | **CAUGHT** — `GUEST_HV: second mutable borrow while one is live`. A degenerate always-closed flag fails the other half. |
| 4 | Leak the claim across the `eret` (restore the pre-arc shape) | **CAUGHT** — `GUEST_HV: second mutable borrow…` |
| 5 | Un-scope the `BlkDisk` borrow (restore the pre-arc shape) | **CAUGHT** — `BLK_DISK: second mutable borrow…` |

Mutations 1 and 3 are deliberate opposites: they kill the two degenerate mechanisms (never-set,
never-cleared) that could otherwise fake the witness. Neither can print the marker.

**Row 2 is the #39 result and it is the honest one.** `assert_boot_cpu` carries **no content on any
path this boot takes**, because `_start`'s affinity gate already owns class 1 unconditionally. The
exercise *localizes* the guard to its true owner: the "single boot CPU" claim belongs to five
instructions of assembly, not to nine Rust comments. `assert_boot_cpu` is kept — one `mrs` on a trap
path — because it covers a core that reaches hypervisor code *without* passing the reset entry (a
future AP bring-up, a non-PSCI or real-hardware reset), which is precisely the case `_start` cannot
see. But it should not be mistaken for the load-bearing part of this arc. **The exclusion flag is.**

---

## 5. Scope, stated plainly

**This arc does not enable SMP and does not make anything SMP-safe.** A second CPU still cannot run
hypervisor code. What changed is the *failure mode*: an AP's `compare_exchange` loses and the machine
**stops**, instead of nine `unsafe` blocks silently ceasing to be sound at once.

SMP was assessed and deliberately not attempted. It is not an arc but a program — AP bring-up, per-CPU
stacks and exception stacks, per-CPU VTTBR/VMID management, TLB shootdown, and a serialization
decision over `hv-core`'s `Hypervisor` (a *model* question, under a standing do-not-touch). Worse, it
changes the **statement**: the non-interference theorem is over a sequential transition system, so
interleaving the machine underneath a proof of it is exactly the #37 hazard.

## 6. Residual

1. **A runtime flag is a check, not a proof.** It catches a violation on the path actually taken; it
   does not prove no path violates. The compile-time half (bounded guard lifetimes) is the stronger
   of the two, and it is what makes the ~50 converted borrow sites statically exclusive.
2. **The publication obligation (class 2) is unchanged by this arc.** It remains a reasoned argument
   living with the barriers in `enable_stage2`; VMID/TLB tagging is TCG-invisible (#23). This arc
   *named* the second agent; it did not machine-check the barrier.
3. **`hv-core`'s `Hypervisor` remains single-threaded by construction.** The one-big-lock vs
   per-domain serialization question is deferred, named, undecided.
4. **`_start`'s gate covers the reset entry path only.** A non-PSCI or real-hardware path entering
   elsewhere is covered by `assert_boot_cpu` — which, per §4 row 2, has never been observed to fire.
5. **`BootCell::as_ptr` is an un-checked hole by design** (two trampoline hand-off sites). It is
   narrow and documented, but it is the one place the exclusivity argument is still prose.
6. **Deferred stronger form:** thread a single `&mut` world token from the three EL2 entry points
   (`rust_main`, `handle_guest_sync`, `handle_guest_irq`) so exclusivity is compile-time *everywhere*
   interior and the runtime flag is needed only at the three mint points. Correct shape; a refactor
   across 5,000 lines of `guest.rs`, so out of scope here.
