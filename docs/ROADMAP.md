<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Baleen roadmap — from a proven model to a "slim Qubes"

*The model is done (`docs/TIER-B/C/D`): `hv-core` is proven ∀-N, both directions of
non-interference — a domain cannot be **affected** by (integrity) nor **learn** from
(confidentiality) another except through authorized channels. This doc is the path from that
proven **model** to a real, running system you can use. It is written to the same discipline the
proofs were: babystep every layer, diamond it, audit it, never skip ahead, and mark honestly where
the word "verified" applies and where it stops.*

## The target: a greenfield "slim Qubes" — and why not Xen-compat

The capstone is **not** a Xen-compatible hypervisor and Qubes is **not** a dependency. The Xen
personality (`baleen-xenabi`) is **dropped**. Matching Xen's 20-year organic ABI bug-for-bug would
be the single most expensive path, would drag Xen's unproven semantics onto our clean core (killing
the proof's value at the emulation boundary), and would leave us subordinate to two upstreams
forever. Qubes is an **architecture** — a set of security patterns — not code we must run.

So we build those patterns fresh on the proven core, using **hardware virtualization + virtio**:
unmodified guests (Linux) think they are on generic virtual hardware and use the virtio drivers
they already ship. No guest needs to know Baleen exists; no Xen ABI is implemented. The small proven
`hv-core` stays the trusted computing base, and every layer above is designed against our own clean
`HvCall` ABI so the proof's guarantees flow **all the way up**.

**"Slim Qubes" is scoped to the disposable-and-vault workflow — the part of Qubes that Baleen
proves most directly, done better:**

- **Disposable VMs** spawned from a template — run, then destroyed. *This is exactly the proven
  lifecycle* (`DomainCreate`/`DomainDestroy`, clean-shell, ID-reuse soundness).
- **A vault** — an offline, no-network VM for secrets. *This is exactly the non-interference
  property*: a domain with no grant/channel/network is provably isolated.
- **Near-bare-metal performance**, GPU included — a first-class goal, and the main thing to *beat*
  Qubes on (Qubes has weak GPU support). CPU/RAM are near-metal for free under hardware virt; the
  GPU is the hard, high-value pillar.
- **Direct device attach** — data USB (a password stick, a backup drive) to a disposable; keyboard
  and mouse handled by a trusted input/GUI domain (never passed through — see the method note in
  Phase M6).

## The method (non-negotiable — the same discipline as A→D)

The tiers A→D worked because of a rhythm, not heroics. It carries over verbatim to the build:

1. **Babystep.** One layer per arc. A layer is not started until the one below is green and audited.
   Never skip ahead — the temptation to "just get a guest booting" before the metal seam is diamonded
   is exactly how unproven assumptions get load-bearing.
2. **Spike first, measure, then scale.** Prove one thin vertical slice of a layer end-to-end before
   building it out — the Kani-bridge / enumerator-bridge move. Surface the cost before committing.
3. **Diamond each layer.** Each layer states its own invariants and gets held to them: a *property*
   to preserve, a *check* that it holds, and — where the layer touches isolation — a *model +
   proof* in `hv-core` before the code that relies on it. (Phases that extend isolation, e.g. DMA
   and GPU-memory, loop back to `hv-core` + Verus, not just implementation.)
4. **Architecture audit between every layer.** The design-lesson #17 move — try to *break* the new
   layer's isolation on paper, against every layer below, before moving on. A clean audit is a valid
   result and the confidence artifact; a found gap is cheaper here than three layers later.
5. **Mark the verified scope, per layer, honestly.** Every layer is one of: *extends the proof* (new
   `hv-core` invariant + Verus proof), *refines the proof* (implementation shown to realize the
   model, validated functionally — see `docs/QEMU-AND-METAL.md`), or *unverified plumbing* (no
   isolation content; say so plainly). The word "verified" applies to the first two only, and the
   ledger at the bottom of this doc tracks which is which.

## The phases

Each phase lists its **see-it moment** (the working demo), the **new work**, the **diamond + audit**
checkpoint, and **honest flags** (does it extend or only refine the proof; does it need real
hardware; platform tension).

### M3 — Metal bring-up: "it's alive"
- **See-it:** `hv-metal` boots to EL2 under QEMU, claims the virtualization hardware, prints "hello"
  over the PL011 UART. No guest yet.
- **New work:** the first real `unsafe`; a real implementation of the `hv-hal` fence (`GuestMemory`
  over real page tables, `TimeSource` over the ARM generic timer, `VcpuOps` over real vCPU context).
- **Diamond + audit:** the fenced `unsafe` core is minimal and every `unsafe` block is justified
  against the same fence the proof assumes; audit the fence boundary — the proof trusts the HAL to
  behave as its traits promise, so this is where that trust is either earned or named as an
  assumption.
- **Flags:** *refines* the proof (the HAL realizes the model's southbound assumptions). QEMU-sound.

### M4 — First native guest: the proof touches reality
- **See-it:** one EL1 guest (native `HvCall` ABI) traps to EL2; a hypercall is routed into `hv-core`
  and serviced; and the **negative-isolation test** — the guest touches unauthorized memory and is
  **faulted by the real Stage-2 tables generated from the model's `p2m`**.
- **New work:** trap/exception handling at EL2; the `p2m → real AArch64 Stage-2 page tables`
  translation; the vCPU run loop.
- **Diamond + audit:** the crucial refinement — *the emitted page tables realize the model's
  `p2m`*. Ideally a checked property (the generated table denies exactly what the model says it
  should); at minimum the negative-isolation test as the bridge. Audit the model→hardware
  translation for every access class (read/write/execute, foreign, superpage).
- **Flags:** *refines* the proof (this is the model→metal bridge for CPU-access isolation).
  QEMU-sound for the functional fault behavior.

### M5 — Disposables + vault: the isolation thesis, live
- **See-it:** a control domain spawns two isolated **Linux** guests via hardware-virt + virtio
  (virtio-blk, virtio-console); one is a **no-net vault**; a disposable boots from a read-only
  template + copy-on-write overlay, runs, and is destroyed clean.
- **New work:** the control domain (create/wire/tear-down); virtio backends (block, console);
  copy-on-write template storage; fast boot.
- **Diamond + audit:** the disposable teardown *is* the proven lifecycle — bridge the running
  control domain's create/destroy to the `hv-core` invariants (`DeadDomainNotClean`, ID-reuse,
  clean-shell), so a destroyed disposable provably leaves nothing and a reborn slot inherits nothing.
  The vault's isolation *is* non-interference — audit that a no-net vault truly has no authorized
  channel to anything. Extend the enumerator/bridge to the control-domain transitions.
- **Flags:** mostly *refines* the proof (cashing in the lifecycle + non-interference results); the
  virtio backends are *plumbing* (no isolation content beyond the channels the proof already covers).

### M6 — Trusted input/GUI domain: a usable desktop
- **See-it:** click between windows, type into the focused disposable; each VM's windows carry an
  unmistakable focus/identity indicator (colored borders); the vault is visibly distinct.
- **New work:** the trusted input/GUI domain — owns the physical keyboard/mouse, **injects virtual
  input events (virtio-input) into the focused VM**, and composites per-VM windows. *Keyboard and
  mouse are never passed through to a guest* — input is a shared, focus-routed resource, so
  passthrough is the wrong tool (you could never type into a second VM). This domain replaces three
  passthrough problems (keyboard, mouse, per-window display) with one trusted component.
- **Diamond + audit:** this domain is now critical TCB — it sees every keystroke and decides who
  gets it. State and check the security properties: **input reaches only the genuinely-focused VM**
  (no VM can spoof focus to steal keystrokes destined for the vault), and **focus is unspoofably
  indicated** to the user. Audit its attack surface hard — it is the crown-jewel component.
- **Flags:** *extends* the isolation story (input-routing + focus-integrity are new properties worth
  modeling); the compositor internals are large *plumbing* with a small critical-security core.

### M7 — Data-device attach + IOMMU: the DMA story
- **See-it:** plug in your password-manager USB → it attaches to the vault/disposable, not dom0; a
  backup drive attaches to a disposable — each DMA-isolated from every other VM.
- **New work:** two tiers. *Easy:* **device forwarding** (a proxy over the RPC layer — sufficient
  for a password stick or a backup drive, needs no special hardware). *Hard:* **IOMMU/SMMU +
  controller passthrough** for direct-driver access, which DMA-isolates an assigned controller.
- **Diamond + audit:** the hard tier **extends the model** — DMA isolation is *not* in `hv-core`
  today (the proof covers CPU-initiated accesses only). New invariants + a new seam + Verus proofs
  for "a device assigned to VM-A cannot DMA into VM-B," then the implementation refined against it.
  Audit the DMA boundary as its own isolation surface.
- **Flags:** forwarding = *plumbing*; passthrough = **extends the proof** *and* is the first phase
  that genuinely **needs real hardware** — QEMU cannot validate SMMU/DMA isolation
  (`docs/QEMU-AND-METAL.md`).

### M8 — GPU acceleration: near-bare-metal disposables (the big pillar)
- **See-it:** a disposable runs something GPU-heavy at near-native speed.
- **New work:** **virtio-GPU with acceleration** (virtio-gpu + Vulkan/venus, native contexts) — shared,
  accelerated GPU across VMs *without* full passthrough (passthrough gives only one VM the GPU, is
  painful to hand to a disposable and reclaim, and is a non-starter on Apple Silicon). Plus the host
  GPU stack.
- **Diamond + audit:** GPU memory is a **new isolation surface with a hard confidentiality problem**
  — GPUs historically leak between contexts. State and check that one VM's GPU work cannot read
  another's GPU memory; the host GPU driver becomes trusted TCB (a large one — an honest tension:
  "GPU + verified isolation" is where the verified story is hardest to keep). Audit GPU-memory
  isolation as its own surface, and name the trusted GPU driver as an assumption.
- **Flags:** **extends the isolation story** (GPU-memory non-interference), **needs real hardware**,
  and carries the sharpest **platform tension** — near-metal accelerated GPU wants **x86 + a standard
  open GPU (AMD/Intel)**; the Apple-Silicon dev machine is great for everything *up to* here but is
  the wall for accelerated-GPU work.

### Capstone — "slim Qubes"
The assembled system: GPU-accelerated near-bare-metal **disposables**, an offline **vault**, direct
**data-device attach**, and a **trusted input/GUI domain** — greenfield, virtio, no Xen, on the
proven `hv-core`. The parts of Qubes you actually use, on a provable core, with the GPU story Qubes
lacks.

## Near-term execution — the first arcs (M3 → M4)

The phases above are the shape; this is the concrete arc-by-arc sequence to *start*, each an arc in
the same commit → diamond → audit → CI-green rhythm the model was built with. Each arc is one PR.

### Arc 0 — the metal dev + test loop *(the enabling move — do this first)*
Stand up the loop before any hypervisor logic, so every later metal arc lands with the same
discipline: a `hv-metal` crate (a standalone crate, excluded from the workspace like `hv-fuzz`, and
the **only** crate that overrides the `unsafe_code = "forbid"` fence — in its own manifest), an
`aarch64-unknown-none-softfloat` bare-metal target with a minimal linker script and an assembly
entry, a `cargo xtask qemu` launcher (`qemu-system-aarch64 -M virt,virtualization=on -cpu max
-nographic`), and a **headless QEMU boot-test in CI** (boot, assert a serial marker, kill on
timeout) so "diamond → CI-green → merge" stays alive on the metal side.
*See-it: the binary boots on the emulated CPU and prints a marker, testable in CI.*
*Why first: without the green-CI ratchet, metal work loses the rhythm that made the model work.*

### M3 — metal bring-up
- **Arc 1 — "hello" over PL011.** MMIO to the UART (`0x0900_0000` on `virt`), a tiny `write_str`; CI
  asserts the banner. *First observable life.*
- **Arc 2 — EL2 + exception vectors.** Confirm `CurrentEL == EL2`; set `VBAR_EL2`; a default handler
  that decodes `ESR_EL2` and prints instead of hanging. *A fault becomes diagnosable.*
- **Arc 3 — claim the virt extensions + run the brain on metal.** Configure `HCR_EL2`; `TimeSource`
  over `CNTPCT_EL0`; link `hv-core`, construct a `Hypervisor`, dispatch a synthetic `HvCall` on the
  bare CPU and print the result.
  **🔍 Architecture Audit #1 — the fence:** enumerate what `hv-core` *trusts the HAL to guarantee*,
  confirm the metal HAL honors each (or name the assumption), and fill in M3's ledger rows.
  *See-it: the diamonded brain is alive at EL2 and serviced a hypercall on (emulated) hardware.*

### M4 — first guest + the bridge *(the proof touches reality)*
- **Arc 4 — trap-and-service.** A trivial EL1 guest (`HVC`), its EL1 context, Stage-2 tables from a
  minimal `p2m`, `eret` in, handle the trap → decode to `HvCall` → `hv-core` → return.
- **Arc 5 — real `p2m` → Stage-2 + the negative-isolation test.** Translate the model's `p2m` into
  real AArch64 Stage-2 descriptors; a guest touching unauthorized memory faults to EL2.
  **🔍 Architecture Audit #2 — model→page-table refinement:** does the emitted table deny *exactly*
  what the model says, across read/write/execute/foreign/superpage?
  *See-it: **the proof touches reality** — the guest is faulted by the real tables generated from the
  proven `p2m`.*

After Arc 5, **M5** (control domain + virtio-blk/console + disposable-from-template + a no-net vault)
is where it stops being a demo and becomes a *system* — and it mostly cashes in the lifecycle and
non-interference proofs, so it should move fast.

**Two honest notes on the phase change:** (1) iteration slows — QEMU boot cycles are seconds, not
the instant enumerator; the Arc-0 CI boot-test is what keeps that from eroding discipline. (2) This
is the first `unsafe` (MMIO, page-table writes, system-register pokes); the fence audit (#1) exists
precisely to keep that surface minimal and justified — the same "name exactly what's trusted" move
as the proofs.

## The two hard pillars (called out, because they carry the risk)

- **GPU acceleration (M8)** — first-class, and the main way to *beat* Qubes. The realistic path is
  virtio-GPU acceleration, not passthrough. The honest cost: a large trusted host GPU driver and a
  genuinely hard GPU-memory confidentiality property. Highest value, highest risk.
- **IOMMU / DMA isolation (M7)** — the security substrate for real device passthrough. It **extends
  the proof** (new `hv-core` model + Verus) and is the first thing that **needs real hardware**. For
  the *described* workflow (a password stick, a backup drive) *forwarding may cover it entirely* — so
  the hard controller-passthrough tier might be optional for your actual use.

## Platform reality (name the fork)

The Apple-Silicon dev machine is ideal for **M3–M6** (isolation, disposables, vault, input/GUI,
near-metal CPU/RAM) — same-architecture, no cross-emulation, fast loop. But **M7 (DMA/IOMMU) and M8
(accelerated GPU) pull toward x86 hardware with a standard open GPU**, the same territory Qubes
lives in — because Apple gates EL2 and Apple's GPU has no passthrough/virtualization path a
hypervisor can use. So: build and demo the thesis on ARM through M6; expect a real-hardware, likely
x86, phase for the two hard pillars. `hv-core` doesn't change across the fork (that is the whole
point of the `hv-hal` fence); only the metal layer does.

## The honesty ledger — what "verified" covers, per layer

| layer | relation to the proof | needs real HW? |
|---|---|---|
| `hv-core` (M0) | **proven** ∀-N, both non-interference directions | — (it's the model) |
| M3 HAL / metal | *refines* (realizes the model's southbound traits) | no (QEMU-sound) |
| M4 Stage-2 gen | *refines* (model→page-table bridge; negative-isolation test) | no (QEMU-sound) |
| M5 disposables + vault | *refines* (lifecycle + non-interference cashed in) | no (QEMU-sound) |
| M6 input/GUI domain | *extends* (focus-integrity) + plumbing | no |
| M7 DMA / IOMMU | **extends** (new `hv-core` DMA-isolation proof) | **yes** |
| M8 GPU memory | **extends** (GPU-memory non-interference) + big trusted driver | **yes** |

Two standing caveats carry through every layer: the proofs cover the **model**, and the metal
enforces it only insofar as each layer *refines* or *extends* it as marked (`docs/QEMU-AND-METAL.md`
draws the emulation-vs-metal line); and the timing/side-channel surface (caches, contention) is
outside both the model and QEMU — an M7/M8-and-beyond concern that needs new design (constant-time
discipline, SMMU config), not just testing.

## One-line summary

Build a greenfield, virtio-based **slim Qubes** — GPU-accelerated near-metal disposables, a vault,
direct device attach, a trusted input/GUI domain — on the proven `hv-core`, one diamonded and
audited layer at a time, never skipping ahead, marking honestly at each layer whether "verified"
still applies. Xen is not a dependency; the proof is the foundation.
