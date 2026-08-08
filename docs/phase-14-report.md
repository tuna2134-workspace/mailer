# Phase 14 report

`mail-sieve` provides a panic-free bounded parser and evaluator for the core Sieve flow: `require`, `if/else`, `header`, `address`, `envelope`, `exists`, `size`, `not`, `keep`, `discard`, `fileinto`, `redirect`, `reject`, and `set` variables.

Execution enforces instruction count, nesting depth, redirect count, and explicit capability checks. Unsupported extensions are rejected rather than silently accepted. ManageSieve transport, vacation generation, notification delivery, and spam/virus scanner results remain injected policy/service boundaries.
