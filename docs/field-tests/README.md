# Field tests

First-party field tests: the project running Bellbook against a real workload
to produce evidence about whether a design serves its purpose. They are the
first-party half of the adoption gates described in
[VISION.md](../VISION.md) - the evidence that may justify advancing a design
ahead of external adoption, recorded so that practice and the RFCs cannot
quietly diverge.

Each report states what was actually run (real code, real measurements, the
published artifacts under test), what the run answered, and every friction it
surfaced - including the ones not worth acting on. A field test that finds
nothing is a result too.

These reports are evidence records, not fixtures: they are not executed by
CI (they need the published packages and, often, an external repository).
Where an RFC pre-registers a criterion measured by a field test, the report
is the recorded measurement, linked from that RFC's evaluation section.

## Reports

- [`ft2-read-side.md`](ft2-read-side.md) - the RFC-0002 named query set on
  published 0.6.0, over a real best-of-N on `eightbells-canary`. Records
  RFC-0002 section 8, validation criterion 1.
- [`ft3-delivery-receipt-canary.md`](ft3-delivery-receipt-canary.md) - the
  `delivery-receipt-v1` profile on published 0.9.0, first-party half: a real
  delivery on the `eightbells-canary` baseline, a skeptic holding only the
  receipt and the artifacts it names, and three attacks. Rehearses the
  adopter cutover (#135); RFC-0003 criterion 1 stays open until that runs.
