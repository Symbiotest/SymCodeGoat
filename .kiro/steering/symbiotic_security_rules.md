---
alwaysApply: true
always_on: true
trigger: always_on
applyTo: "**"
description: Symbiotic security vulenerability scanner (for Code & IaC)
---
# Security best practices for AI coding

- ALWAYS use **security_scan_files** tool of the **symbiotic-security** MCP each time new code is generated, or modified to scan for security vulnerabilities.
- If MCP return vulnerabilities ALWAYS try to fix issues.
- After each fix and before the end of your task, ALWAYS rescan the code to ensure vulnerabilities were fixed and that there are no newly introduced vulnerabilities.
- Repeat until there is no more issues.




