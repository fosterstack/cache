# Scanner panel — acceptance criteria proven by the auditor's tests

REQ-SCAN ACs implemented in the auditor (scanner-panel rules 7-9, 8(c), 13, 14; owner Oct 2-3). REQ-AUD-18 AC1 keeps
auditor paths out of test-evidence/, so the trace lives here (as the CVE auditor matrix does for REQ-AUD); the
requirements check lists these ACs as named residuals pointing here until the owner decides (outbox: trace-vs-layout).

| AC | tested by |
|---|---|
| REQ-SCAN-007-AC1 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC1 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC10 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-008-AC2 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC3 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-008-AC4 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC5 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-008-AC6 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC7 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC8 | `bin/tests/test_panel.py` |
| REQ-SCAN-008-AC9 | `bin/tests/test_panel.py` |
| REQ-SCAN-009-AC1 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-009-AC2 | `bin/tests/test_panel.py` |
| REQ-SCAN-009-AC3 | `bin/tests/test_panel.py` |
| REQ-SCAN-009-AC5 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-013-AC1 | `bin/tests/test_panel.py` |
| REQ-SCAN-013-AC3 | `bin/tests/test_panel.py` |
| REQ-SCAN-013-AC4 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-014-AC1 | `bin/tests/test_panel.py` |
| REQ-SCAN-014-AC2 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-014-AC3 | `bin/tests/test_panel_io.py` |
| REQ-SCAN-014-AC4 | `bin/tests/test_panel.py` |
