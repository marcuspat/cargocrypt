# Retracted: This performance report overstates reality

This file previously presented performance testing as "PASS"/"EXCELLENT" across the board, including "10-1500x faster" comparisons and a "production-ready" verdict.

An internal audit (August 2026) found this framing misleading:

- The report's own text states testing was "performed using simulated cryptographic operations representative of production workloads" -- these are not measured end-to-end production runs.
- The comparison baseline ("RustyVault") is explicitly simulated, not a real measured competitor, so the "500x / 1500x faster" figures are not a real head-to-head benchmark.
- The report concludes CargoCrypt has "production-ready characteristics," which does not hold: as of this audit, `cargo test --no-run` fails to compile.

This file is kept in place (rather than deleted) so the retraction is visible where the original claims were. See the repository's README for accurate, current information about this project's capabilities and status.
