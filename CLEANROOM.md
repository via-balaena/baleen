<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Clean-room provenance policy

Baleen aims to run real Xen guests by implementing **Xen's ABI as a specification**,
without deriving from Xen's GPL source. Baleen is dual-licensed Apache-2.0 / MIT;
that is only defensible if no GPL code — and no design copied from reading GPL code
— makes its way in. This file is the standing rule that keeps that true.

## The rule

> When Xen's behavior informs any Baleen design or code, the **only** permissible
> references are: published specifications and documentation, header/ABI definitions
> under a permissive or clearly ABI-purposed license, observed behavior of a running
> system (black-box differential testing), and the XTF test suite as a conformance
> oracle. **Never** the Xen hypervisor's GPL source (`xen/` in xen.git), and never a
> design reconstructed from having read it.

This is about **provenance of influence**, not about which crate you are editing. A
generic `hv-core` state machine is still tainted if it was shaped by reading GPL
source to "understand how Xen does it."

## When it starts: M2, not M5

The legally-sensitive *artifact* — the `baleen-xenabi` personality with Xen's
structs and hypercall numbers — is built last (M5). But the *risk* is earlier: the
first time you reach for Xen as a reference. **Event channels (M2) are the likely
first such moment** — they are generic in the core, but Xen is the obvious thing to
look at. So the discipline is live from M2 onward, even though it costs almost
nothing to adopt now.

The rule is cheap before it is needed and impossible to retrofit: you cannot un-see
GPL source after it has shaped a design already sitting in the generic core.

## Permitted sources (use these)

- The Xen public documentation, wiki, and design docs.
- Public headers describing the ABI / wire format (hypercall numbering, struct
  layouts, PVH boot protocol) — the interface, not the implementation.
- Xen's published ABI/interface specifications and XSA advisories.
- **Observed behavior**: run a stock Xen, poke it, record what it does. Differential
  testing against a real Xen is a first-class, encouraged reference.
- **XTF** (Xen Test Framework) as a conformance oracle: passing XTF is evidence of
  ABI faithfulness and does not require reading hypervisor internals.
- General OS/virtualization literature, papers, and other hypervisors under
  permissive licenses.

## Forbidden sources (do not open)

- The Xen hypervisor GPL source tree (the `xen/` directory of xen.git) — for any
  purpose, including "just to understand it."
- Any GPL-licensed reimplementation or fork of the same, used as a design crib.
- Design notes, patches, or explanations that quote or paraphrase the above.

## Logging what you referenced

For any non-trivial ABI or behavior-matching decision, note the source in the commit
message or a `docs/provenance/` entry: *what* you were matching and *which permitted
source* told you. Cheap to write now; it is the evidence that the clean-room held if
it is ever questioned. Prefer a one-line trailer, e.g.:

```
Provenance: Xen PV ABI doc §evtchn; behavior confirmed against Xen 4.x under hv-sim diff.
```

## If in doubt

Stop before opening the source, not after. If a design decision seems to *require*
reading GPL internals, that is a signal to (a) find the spec, (b) derive it from
observed behavior, or (c) ask — never to open the file "just this once."
