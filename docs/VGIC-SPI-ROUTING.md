<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# ⑱-6 — the guest aims an interrupt, and the hypervisor obeys

*The last of the three residues ⑱-2 declared, and the second of the two routing axes ⑱-5 opened.*
*⑱-5 decided which vCPU a guest's own IPI names; this decides which vCPU a **device** interrupt goes*
*to — and the guest chose that too, by writing `GICD_IROUTER<n>`.*

---

## 1. The residue, and the condition that expired

`hv-vdev/src/gicv3.rs` carried this from ⑱-2:

> **`IROUTER` is recorded, not honoured** — every SPI can only land in one place.

It was pinned by a Kani harness so it could not drift into a half-implementation, and it named the
reason it was right to leave open:

> it needs a second vCPU per guest to *matter*, so implementing it now would add unexercised code to
> the guest's device surface

That is design-lesson #71 and III-2's *"deferred for want of a consumer"*. **`VCPUS_PER_GUEST` is 2
and both vCPUs run**, so the condition is met and the same rule that justified waiting now requires
the opposite.

★ **The transferable part is the shape of the deferral, not the rung.** A bare *"later"* can never be
discharged — nothing says when. A deferral with its expiry condition attached is a claim that becomes
checkable, and this one was discharged by reading it and noticing the constant had changed under it.
Two of the three ⑱-2 residues have now closed that way.

## 2. What was actually wrong

Before this rung, every SPI EL2 delivered went into **the list registers of whichever vCPU was on the
pCPU**. With one vCPU per guest that is the only possible answer and is correct. With two it is a
coin flip that happens to be right about half the time — and, worse, it is *silently* right often
enough that a casual witness confirms it (see §5, which is the most useful thing in this document).

## 3. The seam: `hv-vdev/src/irouter.rs`

A pure decode of a guest-written `u64`, deliberately the same shape as `hv-vdev/src/sgi.rs`:

```rust
pub const fn decode(value: u64) -> SpiRoute;
impl SpiRoute {
    pub const fn is_any_of_n(&self) -> bool;
    pub const fn targets(&self, aff: u64) -> bool;   // takes a PACKED AFFINITY
}
```

`targets` takes what `gicv3::vcpu_affinity(v)` returns rather than a vCPU index, so this module never
learns baleen's vCPU→affinity mapping — which already has exactly one derivation, and which ⑱-3b-i
spent a rung reducing *to* one. `vcpu_affinity` now has three consumers: `GICR_TYPER`, `hv-metal`'s
`guest_mpidr`, and this.

Two properties fall out of the shape rather than being checked:

| property | why it is structural |
|---|---|
| a route naming a foreign cluster targets **nothing** | no `vcpu_affinity` value can equal a non-zero `Aff1`/`Aff2`/`Aff3` |
| a route names **at most one** vCPU | `targets` is an equality against one recorded affinity — there is no list to have two bits set in |

The second has no analogue in `sgi.rs`: an SGI names a *set* on purpose. It is what lets
`hv-metal`'s delivery loop `return` after the first match and lets the verdict assert a count.

## 4. `IRM` (1-of-N): a declaration, not a policy

Bit 31 means *"route to any PE participating in 1-of-N distribution"*, implementation's choice. That
is a genuine fork, and picking a PE would be hypervisor policy no guest asked for and no artifact
could check.

So this port does not pick. **`GICD_TYPER.No1N` (bit 25) is set** — the architecture's own provision
for saying 1-of-N is unavailable — and the decode is then total over everything a *conforming* guest
can ask for. Design-lesson #202: prefer a declaration to a guess, and it hands you a second,
independently-produced witness — here a real kernel reads `No1N` and never sets `IRM`.

A guest that sets it anyway targets no vCPU (`SPIS_UNROUTABLE`, counted and reported). ⚠ Deliberately
**not** a halt: a `park()` reachable by writing one register would take the peer domain down with it,
which is the defect ⑱-5 removed from the SGI path.

`the_distributor_declares_one_of_n_unsupported` is the harness that ties the two together. Without
it, "the decode refuses `IRM`" would be a behaviour rather than a justified one, and a later
"simplification" of `GICD_TYPER_VALUE` would leave the guest told it could use a mode EL2 silently
drops.

## 5. ★★ THE WITNESS, AND THE FIRST VERSION OF IT PROVED NOTHING

This is the part worth reading if nothing else here is.

### 5a. What the guest does

`guest-init.sh` resolves the UART's IRQ from `/proc/interrupts` — **the kernel prints its own IRQ
number and the GIC INTID side by side**, so the guest and EL2 are demonstrably naming the same
interrupt rather than two numbers that happen to agree:

```text
 13:          0          0    GICv3  33 Level     uart-pl011
```

and writes CPU1's mask to its `smp_affinity`. arm64 Linux's `gic_set_affinity` then writes
`GICD_IROUTER<33>`, which traps into hv-metal's emulated distributor. **Nothing here is a new EL2↔
guest channel**: the trigger is a register the kernel writes for its own reasons.

MEASURED on `main` before the witness was designed (design-lesson #186): that row is **zero on both
CPUs across an entire boot** — the emulated PL011 never raises — so the baseline is not merely low,
it is empty.

### 5b. The version that was wrong

The injection was originally made **at the routing write itself**. The gate went green. The guest's
own `/proc/interrupts` reported `cpu0=0 cpu1=1` — the interrupt had landed on CPU1, exactly as asked.

**It proved nothing.** The `smp_affinity` write is executed by whatever CPU runs PID 1, which was
CPU1 — so the vCPU the guest routed to and the vCPU that happened to hold the pCPU were *the same
one*. EL2's own counters said so plainly (`1 delivered, 0 routed`: it had taken the running-vCPU
path), and **an implementation that ignored `GICD_IROUTER` entirely would have produced a byte-
identical guest log.**

⚠ Design-lesson #198 — *a witness's discriminator can be a property of the fixture* — walked into,
head first, one rung after it was written down.

### 5c. The fix: fire where the two answers differ

The witness is now **armed** at the routing write and **fired** from a `WFI` trap taken on a vCPU the
route does *not* name. Then:

* the sibling path is the only one that can run, so "delivered to the running vCPU" is structurally
  impossible for it;
* the verdict asserts `routed == 1 && delivered == 0` rather than merely counting;
* honouring the routing and ignoring it lead to **different CPUs**, so the guest's own per-CPU counts
  can tell which happened.

The `WFI` path is the right second half because `guest-init.sh`'s one-second idle window produces
hundreds of them on *both* vCPUs — a moment satisfying the condition is reached reliably rather than
hoped for.

### 5d. What the gate now asserts

Two accounts, produced by two different parties, neither taking the other's word:

| who | marker | what it is |
|---|---|---|
| EL2 | `baleen: vspi OK` / `baleen: vspi FAIL` (forbidden) | its own routing decision and the one-disposition identity `named == delivered + deferred + routed` |
| the kernel | `baleen-spi-counts: cpu0=0 cpu1=1` (required, per dom) | which of **its** CPUs ran the handler, counted by its own interrupt path |

## 6. The removed-fix probe

`--features spi-route-probe` makes `deliver_spi` ignore the route and take whichever vCPU is on the
pCPU — the pre-⑱-6 behaviour, restored on purpose. Run by hand (it costs a whole real-Linux boot);
the result is stable and is here.

| | unmodified | `spi-route-probe` |
|---|---|---|
| `[dom 1] baleen-spi-counts:` | `cpu0=0 cpu1=1` | **`cpu0=1 cpu1=0`** |
| `[dom 2] baleen-spi-counts:` | `cpu0=0 cpu1=1` | **`cpu0=1 cpu1=0`** |
| EL2 dispositions (both doms) | `0 delivered + 1 routed` | **`1 delivered + 0 routed`** |
| `baleen: vspi FAIL` | absent | **present** |
| gate | green | **red** |

★ **Both halves flip, independently.** The guest's accounting and EL2's verdict are not two readings
of one counter — one is Linux's interrupt path, the other is hv-metal's delivery path — and the probe
kills both, on both guests. That is what makes `cpu0=0` carry as much of the property as `cpu1=1`.

⚠ The probe config is in `METAL_LINT_CONFIGS`. It is booted by no gate, which is exactly why: a probe
nothing lints can stop compiling without anyone noticing until the day its evidence is least
replaceable (design-lesson #212).

## 7. What this rung does **not** claim

* **No device in this machine raises an SPI for a Linux guest.** The emulated PL011 never asserts its
  interrupt (§5a's measured zero baseline is the same fact), so the SPI EL2 delivers is one it
  injects deliberately. What the guest supplies is the part that matters and the part that was
  missing — **the routing decision** — but "a real device interrupt was routed" is not a sentence
  this repo can write yet, and the first real SPI source will use `deliver_spi` rather than adding a
  second path.
* **One SPI, one routing change, one injection.** The harnesses quantify over every INTID and every
  64-bit routing value; the *boot* exercises INTID 33 re-aimed once per guest. The proofs are the
  ∀ evidence, as ⑱-2 said of the multi-redistributor model.
* **`SPIS_UNROUTABLE` is proven, not boot-witnessed.** A foreign cluster and an `IRM` write both
  reach it and both are covered ∀-value, but the shipped guest is conforming and writes neither.
* **Nothing about priority or preemption.** `GICD_IPRIORITYR` is recorded as before, and which of two
  simultaneously-pending vINTs a vCPU takes first is the hardware CPU interface's business.

---

*See also: `hv-vdev/src/irouter.rs` (the decode), `hv-vdev/src/gicv3.rs` (`spi_route`, `No1N`, the
residue list), `hv-verify/src/lib.rs` `device_models` H4c (the proofs and the kill-probe matrix),
`hv-metal/src/linux.rs` (`deliver_spi`, `arm_spi_witness`, `maybe_fire_spi_witness`),
`hv-metal/linux/guest-init.sh` (the guest's half), and `hv-vdev/src/sgi.rs` — the other routing axis,
which this deliberately mirrors.*
