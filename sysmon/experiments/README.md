# Sysmon config experiments

Throwaway Sysmon configuration attempts from the R-016/R-017/R-018 FIM work.
They are kept for provenance, **not** for deployment.

Context: hand-written minimal FIM configs (these files) triggered a driver-load
crash `0xC0000409` on Sysmon 15.21. The confirmed trigger was a `<FileDelete>`
element. The deployment therefore uses the SwiftOnSecurity base config, which loads
cleanly and already emits the events R-016/R-017 need.

| File | Lines | Outcome |
|---|---|---|
| `sysmon-test-fc.xml` | 11 | FileCreate only — minimal probe |
| `sysmon-test-fc4.xml` | 14 | FileCreate variant — iteration 4 |
| `sysmon-test-fc-fd.xml` | 19 | added FileDelete — **crashed the driver** |

Use `../sysmon-config.xml` (minimal, deployable) or
`../sysmon-config-swiftonsecurity.xml` (deployment default) instead.
