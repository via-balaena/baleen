# M5 Arc 6b — a real Linux kernel behind the proven emitter

**Status:** done. `hv-core` / `hv-hal` untouched.

Arc 6a's residual, stated plainly at the time:

> **`linux.rs::build_stage2` still exists.** This arc makes the proven emitter *capable* of hosting a
> real guest; it does not rehost it. The only real Linux guest still runs behind an emitter no proof
> touches. The gap that motivated the work is narrowed, **not closed**.

It is closed now. `linux.rs::build_stage2` is gone, along with that file's own table storage and its
own descriptor encodings. An unmodified Alpine aarch64 kernel boots to `Run /init as init process`
and powers off via PSCI, behind Stage-2 emitted from a real `hv-core` model of **448 super-span
leaves across 56 `L2`-pinned tables**.

---

## 1. One emitter, two configurations

The synthetic guests and the Linux guest need different windows — different RAM base, a device region
for one, a hypervisor-owned code image for the other. They must **not** get different *emitters*;
that is the two-emitters problem this arc exists to end. So the windows became **data**
(`stage2::Windows`, a `const fn` per build) and the emission path is shared, proofs and all.

| | synthetic | real-linux |
|---|---|---|
| guest image | `Some(__guest_ram_start)`, RO+X block | **`None`** — the kernel is inside the mapped RAM |
| super window | 1 frame, own reserved 2 MiB | **448 frames, identity at `0x4800_0000`** |
| device region | none (virtio is trapped, not mapped) | **32 MiB, GICv3 + PL011, Device-nGnRnE + XN** |
| RAM executable | no | **yes — declared, see §2.2** |

---

## 2. Three findings — each a real constraint, not a bug

### 2.1 `hv_core::TABLE_SLOTS` is **8**

A deliberate model abstraction — *"small enough that the `links` table stays bounded"* — not a
hardware fact. One model table therefore holds at most **8 leaves**, so 448 superpages cannot hang
off one, and `hv-core` is untouchable. The metal composes **56 tables**.

This is the refinement doing its job rather than a workaround: the emitted table does not reflect the
model's table *structure* at all. The refinement is over the **leaf set** (Audit #2's leaf-level
reachability scope), so 56 eight-leaf tables and one hypothetical 448-leaf table emit the *same*
Stage-2. The model's shape and the hardware's shape are related by the refinement, not by imitation.

### 2.2 A real kernel executes from its own RAM

The first boot attempt took an **instruction abort, permission fault at level 2** (`EC=0x20`,
`ESR=0x8200000e`) at the kernel entry: Arc 6a made every data leaf execute-never, on the argument
that *"an executable data superpage is a 512-page execute surface."* That argument is right for a
guest whose code lives in a separate read-only image. It makes a real kernel unhostable.

Rather than quietly relaxing a constant, `Layout::sup_executable` makes it a **declared flag that
`verify_encoding` checks exactly**: a config that did not ask for execute cannot silently get it, and
one that did cannot silently lose it. Base-span (4 KiB) leaves stay XN unconditionally; only the
super window — which is what a real guest's RAM is made of — is affected.

**This is a named weakening of the isolation posture for a guest that runs from its RAM.** It is on
the record here rather than buried in a descriptor constant.

### 2.3 Identity needed no new mechanism

The emitter maps `base + m·size` in *both* address spaces, so setting `sup_ipa_base == sup_pa_base`
gives IPA == PA for free — which is what the arm64 boot protocol and the DTB's `/memory` node
require. A case where the existing generality happened to cover the new requirement; checked, not
assumed (#12's habit).

---

## 3. The Linux emission is now verified on its real tables

`verify_encoding` is `selftest`-gated, and `xtask qemu-linux` built with `real-linux` alone — so
**the one real guest's emission was the only one never read back**. `qemu-linux` now builds
`real-linux,selftest`, and the boot reports:

> `selftest: Stage-2 encoding verified (set 0: tables decode to exactly the authorized leaf map;
> image block absent (tables asserted dead); 448 super-span 2 MiB block(s) emitted and decoded;
> device window 32 MiB)`

The whole emitted structure decoded back and every other slot asserted dead, on the real hardware
tables the kernel then runs behind.

The marker also used to say *"image block RO+X"* in a config that has **no image block** — hardcoded
text from when every config had one. It is derived from the layout now. A marker that states
something the run did not check is worse than no marker.

---

## 4. Mutations

| # | Mutation | Result |
|---|---|---|
| 1 | Remove the device pass-through region | **CAUGHT** — `LINUX GUEST TRAP: EC=0x24` (the kernel cannot reach its GIC/UART) |
| 2 | Guest RAM made execute-never (Arc 6a's default) | **CAUGHT** — `EC=0x20`, the fault that found §2.2 in the first place |
| 3 | Device blocks emitted as **Normal memory** | **CAUGHT** — `ENCODING VIOLATION` on the **real emitted tables**, which is exactly what §3 bought |

Row 3 is the one that justifies wiring `selftest` into the Linux path: without it, a device window
mapped as cacheable Normal memory would have booted fine and been wrong.

---

## 5. Evidence, and its limits

- **`cargo xtask qemu-linux` is kernel-gated and NOT part of CI.** The Linux boot is a **local**
  result, run against the final tree. CI covers the synthetic path only (140 checks, both feature
  configs).
- Verus 12 files, **61 verified, 0 errors**; Kani suite re-run; workspace CI green; hv-s2 38 tests.
- `hv-core` / `hv-hal` untouched.

---

## 6. Residual

1. **The Linux guest is one domain with no peer.** This arc puts a real kernel on the proven
   emitter; it does not run *two* isolated real guests. The isolation thesis is still cashed on
   synthetic guests only — a real-guest non-interference witness is a further arc.
2. **Guest RAM is RWX for the Linux config** (§2.2), declared and checked but genuinely weaker than
   the synthetic posture. Splitting a kernel's text from its data would need model-level execute
   permission, which `p2m` does not have.
3. **`sup_executable` is per-emission, not per-leaf.** The model has `writable` but no executable
   bit, so execute cannot currently follow the model the way permission does.
4. **The device region is infrastructure, not model-driven** — no `p2m` edge describes MMIO, so its
   correctness rests on `Layout::validate` plus the decode check, not on the refinement theorem.
5. **The kernel-gated path has no CI coverage**, so a regression in the Linux emission would be
   caught only by someone running it locally.
6. **DMA remains entirely out of scope** — no SMMU work exists, and a real guest driving real
   devices is exactly where that starts to matter.
