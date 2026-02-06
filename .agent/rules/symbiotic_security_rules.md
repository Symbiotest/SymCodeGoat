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
-   [SYM-GR-0001] Security concerns data leaks


# Project Security Settings
# Symbiotic Rules

The following are rules related to security best practice.
You MUST enforce them at all times.


- [SYM-GR-0064] ALWAYS use the ORM's parameterized APIs and query builders; NEVER fall back to raw SQL string concatenation with user input.
- [SYM-GR-0065] NEVER use the ORM's "raw query"/"execute SQL" escape hatches with untrusted data unless all parameters are bound and identifiers are strictly whitelisted.
- [SYM-GR-0066] ALWAYS validate and constrain user input (types, length, format) before passing it to ORM models; do not rely on ORM sanitization alone to prevent injection.
- [SYM-GR-0009] NEVER build SQL or NoSQL queries via string concatenation or $where with user input; ALWAYS use parameterized queries or query builders/ORMs.
- [SYM-GR-0050] NEVER expose Redis directly to the internet; ALWAYS bind to trusted networks only and enforce authentication and TLS for all Redis connections.
- [SYM-GR-0051] NEVER store sensitive data (passwords, tokens, PII, encryption keys) in Redis without encryption or strict TTLs; treat Redis as an untrusted cache, not a secure vault.
- [SYM-GR-0052] ALWAYS validate and sanitize any user-controlled keys or values before using them in Redis commands to prevent keyspace abuse, data overwrites, or injection-like patterns.
- [SYM-GR-0057] ALWAYS enforce least-privilege access to cloud storage (buckets/containers/objects); NEVER make buckets public unless there is a documented, reviewed business need.
- [SYM-GR-0058] ALWAYS enable encryption at rest and in transit for cloud-stored objects; NEVER upload sensitive data over plain HTTP or to unencrypted buckets/containers.
- [SYM-GR-0059] NEVER store secrets, access keys, or credentials in world-readable paths; ALWAYS restrict access via IAM roles/policies instead of embedding credentials in URLs or code.
- [SYM-GR-0060] ALWAYS validate and sanitize user-controlled filenames/paths before using them in cloud storage operations to prevent path traversal, overwrites, or unauthorized object access.
- [SYM-GR-0193] ALWAYS scan and validate dependencies across all programming languages in mixed-language repositories using language-specific security tools (npm audit, pip-audit, bundler-audit, etc.) and maintain a consolidated vulnerability report
- [SYM-GR-0194] ALWAYS validate and sanitize data at language boundaries using strict type checking, input validation, and secure serialization methods when data flows between different programming languages in the same repository
- [SYM-GR-0195] ALWAYS implement containerized builds with pinned language runtime versions and unified CI/CD pipelines that handle all languages consistently to prevent version drift and deployment inconsistencies in mixed-language projects

Any AI-generated code violating these rules must be considered **unsafe, 
non-compliant, and rejected**.

---


