---
alwaysApply: false
always_on: false
trigger: model_decision
description: Symbiotic security vulenerability scanner (for Code & IaC)
---
# Security best practices for AI coding

- ALWAYS use **security_scan_files** tool of the **symbiotic-security** MCP each time new code is generated, or modified to scan for security vulnerabilities.
- If MCP return vulnerabilities ALWAYS try to fix issues.
- After each fix and before the end of your task, ALWAYS rescan the code to ensure vulnerabilities were fixed and that there are no newly introduced vulnerabilities.
- Repeat until there is no more issues.

# Organization security requirements
-   [SYM-GR-0001] **NEVER** suggest logging, printing, or transmitting sensitive data in plaintext

-   [SYM-GR-0004] **DO** use least privilege & role-based access.

-   [SYM-GR-0005] **ALWAYS** encrypt data in transit (TLS 1.2+) and at rest (AES-256 or equivalent)

-   [SYM-GR-0006] **DO** apply pseudonymization/anonymization where possible

-   [SYM-GR-0007] **DO NOT** store CVV, PIN, or SAD after authorization.

-   [SYM-GR-0009] **ALWAYS** use secure, vetted libraries instead of custom crypto.

-   [SYM-GR-0010] **DO** annotate security/privacy-relevant sections with compliance comments

-   [SYM-GR-0011] Sensitive data **MUST** be encrypted at rest and masked in logs.

-   [SYM-GR-0012] Time-critical logic **MUST** use UTC with explicit timezone handling and a precision adapted to data type.

-   [SYM-GR-0013] Sensitive records **MUST NEVER** appear in logs or error messages.

-   [SYM-GR-0014] Data retention policies **MUST** enforce automatic deletion or anonymization of PII past its business/legal lifetime.

-   [SYM-GR-0015] All payment flows MUST use tokenization or vault services—code MUST NOT handle raw card data beyond secure entry.

-   [SYM-GR-0016] Payment operations **MUST** be idempotent with unique transaction IDs or idempotency keys.

-   [SYM-GR-0018] Security controls MUST be applied by default, but pragmatic exceptions may be allowed if they are risk-assessed, documented, and approved—developer convenience can justify controlled trade-offs, never silent ones.

-   [SYM-GR-0020] Security concerns for this organization are data leaks



