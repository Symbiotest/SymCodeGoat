// Real Vulnerability Examples for BASH

// Rule ID: 739 - Improper Control of Generation of Code ('Code Injection')
// Description: This code contains hidden Unicode bidirectional (bidi) characters, which can make code appear differently to reviewers than how it actually executes. Attackers can use these characters to disguise malicious code or change logic flow in a way that's hard to detect.
// TODO: Provide actual vulnerable code

// Rule ID: 1,964 - Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
// Description: The code takes data fetched by a curl command and runs it using eval. This means any code returned from the server will be executed, making your script vulnerable if the server is compromised or malicious.
// TODO: Provide actual vulnerable code

// Rule ID: 1,965 - Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
// Description: Piping data directly from a curl command into bash allows external code from an untrusted server to be executed on your system. This practice is insecure because attackers could modify the server's response to run malicious commands.
// TODO: Provide actual vulnerable code

// Rule ID: 1,966 - Improper Input Validation
// Description: Setting the IFS (Internal Field Separator) variable globally in Bash scripts can change how input is split, potentially leading to unexpected behavior or security issues. This can cause scripts to incorrectly parse user input or files, especially when expanding unquoted variables.
// TODO: Provide actual vulnerable code

