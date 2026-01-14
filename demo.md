# Demo Guidelines

## PR Exercice 

1. **vulnerable.py**
_SYM_PY_0128 - Active Debug Code_
Line 42 > Answer A
2. **vulnerable.go**
_SYM_GO_0028 - Cleartext Transmission of Sensitive Information_
Line 47 > Answer A
3. **vulnerable.ts**
_SYM_JSTS_0050 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')_
Line 8 - 17 > Answer A

## Deep remediation

Deep remediation suggestion can be demoed with the **deep-remediation.go** file. 
Open the webview and you will be suggested to launch a deep remediation.

## False positive 
In the **php/false_positive.php** file, issues will be detected as false positive. 
Open the webview and the remediation process will stop and you will see a false positive banner. 
Click on _learn why_ if you want to show the false positive explanation 

## Test the MCP 

Open the AI chat and for example ask : 
"Refactor transfer() function in @vulnerable.py"
The model should write some code and call the MCP to scan the code and find issues..

# Demo Tips 

## Clear cache

Before starting the demo, clear the cache using the `> Symbiotic Security: Clear Cache` command
CMD+P then `> Symbiotic Security: Clear Cache` 

## Update the repository

Open the terminal in the IDE and run the command : `git reset --hard && git clean -fd && git fetch origin && git rebase origin/main`