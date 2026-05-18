---
name: Feature request
about: A new tool, report type, integration, or behaviour you'd like to see.
title: "[feat] "
labels: enhancement
---

### What you want

<!-- One paragraph. Be concrete about the user-visible change. -->

### Why

<!-- The operational scenario where this matters. "I'm running a red team
     against an Azure tenant and I need X to do Y." Generic "would be cool
     to have X" requests are likely to be deprioritised. -->

### How it might work

If you have a design in mind — flags, scope fields, report file
shapes, command surface — sketch it here. Otherwise leave blank and
we'll discuss.

### Alternatives you've considered

<!-- Existing tools / approaches that almost solve this but don't.
     Helps us understand whether this is "missing capability" vs.
     "different UX for an existing capability". -->

### Scope hygiene

- [ ] This feature respects the **scope guard** — out-of-scope targets
      remain unreachable from the new code path.
- [ ] This feature would not introduce telemetry / phone-home.
- [ ] This feature would not weaken audit-log integrity.

(If you can't tick a box, that's fine — flag it in the description
and we'll work through it.)
