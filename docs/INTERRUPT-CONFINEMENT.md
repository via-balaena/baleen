<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# ⑱-7 / ⑱-8 — the peer probe for interrupts, and the role that made the guard unnecessary

*The memory axis of isolation has had a victim-observed witness since ③-b2b-ii-d: dom 1 reaches for*
*dom 2's RAM and the hardware refuses, on a guest that survives to report it. The interrupt axis had*
*none. This is its counterpart — and the thing it found along the way is worth more than the witness.*

---

## 1. The finding: there was one mechanism, and the code claimed two

`hv-metal`'s `ICC_SGI1R_EL1` handler used to say, of the loop that offers a decoded SGI to each vCPU:

> the affinity a guest names is checked against `vcpu_affinity`, but even a value that matched a
> peer's would never be asked about, because the peer's vCPUs are not in this iteration.
> **Two independent reasons**, and the loop is the stronger one.

**There are not two.** Look at the signature:

```rust
pub const fn vcpu_affinity(vcpu: usize) -> u64      // hv-vdev/src/gicv3.rs
const fn guest_mpidr(vcpu: VcpuIdx) -> u64 { MPIDR_RES1 | vcpu_affinity(vcpu.get()) }
```

**`vcpu_affinity` takes no guest argument.** Dom 1's vCPU 1 and dom 2's vCPU 1 have *identical*
affinity, necessarily and by construction. So the affinity comparison — the first of the two claimed
reasons — is not merely weaker against a peer, it is **vacuous against a peer**, which is the only
case it was invoked for.

★ **The collision is in the function's type, not its arithmetic.** It cannot be repaired by choosing
better numbers, and **no decode under the `hv-vdev` fence can ever confine an interrupt to a guest** —
`sgi::decode` and `irouter::decode` are both handed a bare affinity and have nothing else to go on.
Their "isolation falls out" arguments are true, but they are about *clusters* (an `Aff1`/`Aff2`/`Aff3`
no vCPU has), and every guest's vCPUs live in cluster 0 together.

So the reason count is **one**: a single `g != slot` guard, in two loops, in `hv-metal`. And
`hv-metal` is not a Kani target, so it has no theorem either. Before this rung it had no boot witness
and no probe — the entire interrupt axis of guest isolation rested on an unexhibited comparison.

## 1a. ⑱-8 — and then the guard stopped being a guard

⑱-7 wrote the bound out as an explicit `g != slot` comparison so the mechanism was at least visible.
**⑱-8 removed the need for it.** `Running::own_vcpus()` yields a role — `OwnVcpu` — obtainable only
from the running vCPU, and `PerVcpu::own` is the only accessor that takes one. All four filters are
gone because **there is no peer in the iteration to filter out**.

The fourth site is the sharpest and was the least obvious: **`PSCI CPU_ON`**. `target_mpidr` is `x1`
of a guest-issued PSCI call, and `guest_mpidr` is `MPIDR_RES1 | vcpu_affinity(vcpu)` — no guest
argument — so a peer's vCPU with the same index has the *same MPIDR* and matches exactly. A
guest-chosen register value reaching a cross-guest capability, with one `.filter()` in between.

★ **What the fence buys, stated narrowly: it is against ACCIDENT.** `PerVcpu::at` still exists and
still reaches peers — reports need it, and `wake_blocked_vcpus` spans guests on purpose. A future
author can still deliver across guests; they must now *name a guest index* to do it, which is a
deliberate act visible in a diff rather than the default behaviour of an accessor taking a `usize`.
The removed-fix probe in §4 does exactly that, on purpose.

⚠ **The witness had to change with the mechanism.** ⑱-7's marker counted *refusals*; with no guard
there is nothing to refuse, so that counter would have read **zero while passing** — a witness
measuring nothing (#199, #215). It now counts the **hazard**, which is the number that justifies the
fence existing at all.

## 2. Counting the hazard

⑱-7 made the bound an explicit guard with a counter of **refusals**; ⑱-8 removed the guard, so the
same counter now measures the **hazard** instead — how often an affinity a guest named also described
a peer's vCPU. Both are `baleen: irqconfine OK`, and it is non-zero on every boot, in the hundreds:
MEASURED **249 / 394** (⑱-7, refusals) and **205 / 191** (⑱-8, collisions), varying with workload.

That number is the demonstration that §1's collision is real and continuous — *every* IPI Linux sends
names an affinity some peer vCPU also has — and it is the only thing that would tell a future reader
the hazard is real rather than theoretical.

A **zero** is the `baleen: irqconfine FAIL` case, and it means something worth distinguishing from a
leak: not "an interrupt crossed" but "**the hazard never occurred**". The guests would have stopped
colliding — `vcpu_affinity` gaining a guest argument would do it — and §1's argument would need
re-reading.

## 3. The victim's witness

`guest-init.sh` makes **dom 1 only** raise the CPU-backtrace IPI (`sysrq l`), a real
`ICC_SGI1R_EL1` write trapped and routed by EL2. Then both guests report:

```
[dom 1] baleen-ipi6-total: 1      its own
[dom 2] baleen-ipi6-total: 0      nothing in the machine raises this INTID for it
```

⚠ **IPI6 is the choice because its baseline is zero and it is the only zero-baseline IPI a guest can
raise on demand.** MEASURED across a whole boot: IPI0/1/5 (rescheduling, function call, IRQ work) run
constantly; IPI2/3 (CPU stop) fire at poweroff; IPI4 needs a broadcast timer, IPI7 needs kgdb.

### 3a. ★ One sender, not two — and the first version had two, which could not have worked

The original design had **both** guests raise the IPI, with each asserting `1` and a leak showing as
`2`. That is unsound, for a reason specific to how EL2 delivers to a non-running vCPU:

> **`PendingSet` is a SET.** An INTID leaked from the peer that the victim *also* raises for itself
> coalesces into one entry and **becomes invisible**.

The discriminator would have been 1-vs-2 on a quantity that cannot reliably reach 2. MEASURED with
the probe armed and both guests sending: **dom 1 read `0` and dom 2 read `1`** — noise in both
directions, and not the `2` the design predicted.

With one sender the victim's baseline is **structurally zero**, so 0-vs-1 never needs the set to hold
two of anything. (The sender is picked by RAM window, the same string `baleen-guest-ram:` already
asserts per dom, so a moved window goes red there first rather than silently disarming this.)

⚠ **One other thing can make `[dom 2] baleen-ipi6-total: 0` go red, and it is not a leak:** Linux
raises the CPU-backtrace IPI itself when it detects an RCU stall or a hung task. A dom 2 sick enough
to do that fails this assertion. That is the right outcome — and worth knowing before debugging a red
run as a confinement failure, because it is also *how the probe in §4 actually kills*.

## 4. The removed-fix probe — and it kills harder than the witness measures

`--features no-irq-confinement` makes both loops **honour** a peer match instead of refusing it. That
is not a contrived mutation: per §1 the match is genuine on every boot, so this is exactly what the
code would do if the guest bound were dropped.

| | unmodified | `no-irq-confinement` (two runs) |
|---|---|---|
| `[dom 2] baleen-ipi6-total:` | `0` | **never printed**, both runs |
| dom 2 | powers off cleanly | **wedged — `rcu_preempt detected stalls`, `Offline CPU 1 blocking current GP`** — both runs |
| dom 1's `baleen-spi-counts` row | `cpu0=0 cpu1=1` | run 1 read **cpu1=2**, run 2 read cpu1=1 — see below |
| `[dom 1] baleen-ipi6-total:` | `1` | `1` (dom 1 is the sender; its own) |
| gate | green | **red, and times out** — both runs |

★ **The reliable kill is the victim's DEATH, not a flipped count, and that is the honest reading.**
Dom 2 never reaches its own report, so the designed `ipi6-total` discriminator never prints. Losing
interrupt confinement is an **availability** failure of one guest caused by another's ordinary IPI
traffic — not just an information-flow one.

⚠ **CORRECTION, and it is the kind this document exists to make.** The first version of this table
gave dom 1's `baleen-spi-counts` row reading **cpu1=2** as *"a clean, counted, victim-observed leak"* —
dom 1 having received dom 2's ⑱-6 witness SPI as well as its own. **That was one run.** A second
probe run read `cpu1=1`: dom 2 wedges under the foreign IPI traffic, and whether it survives long
enough to fire its own SPI witness is a race. The leak is real when it appears, but **the signal is
timing-dependent and must not be quoted as a discriminator** (design-lesson #214 — a point inside a
range is not a witness for the range). What is stable across runs is the row above it.

⚠ Run by hand. `cargo xtask qemu-linux-test` reuses **one** log file per process
(`baleen-qemu-linux-<pid>.log`) across its four boot configurations, so only the last survives — use
`cargo xtask qemu-linux` to capture a single config's output, and note it has no wait cap, so a
wedged probe boot runs until killed.

## 5. What this rung does **not** claim

* **No theorem.** `hv-metal` is not a Kani target, so the guard has a boot witness and a probe, not a
  proof. The decodes it sits above *are* proven — and §1 is the statement that those proofs cannot
  reach this property, which is the point.
* **Nothing about a malicious guest choosing affinities.** A guest can write any affinity it likes;
  the guard does not care what it names, only which guest asked. That is the right shape, but it
  means the property is "EL2 offers a decode only its own guest's vCPUs", not "a guest cannot name a
  peer" — it names them constantly, and is refused.
* **One pCPU, one machine.** Both guests time-slice a single physical CPU. Nothing here is a
  statement about interrupt confinement under real concurrency.
* **Only the two routing loops.** Every other path by which EL2 injects (the forwarded timer PPI, the
  ⑱-6 witness, the overflow probes) names its target directly rather than by affinity, and so has no
  guard to lose. That is an argument, not a witness.

---

*See also: `hv-metal/src/linux.rs` (`handle_linux_sysreg_trap`, `deliver_spi`,
`SGIS_FOREIGN_REFUSED`), `hv-metal/linux/guest-init.sh` (the sender and the victim's report),
`hv-vdev/src/gicv3.rs` (`vcpu_affinity` — the signature §1 rests on), `docs/VGIC-SPI-ROUTING.md`
(⑱-6, whose marker turns out to guard the same property on the SPI axis).*
