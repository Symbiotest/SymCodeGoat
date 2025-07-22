// Real Vulnerability Examples for APEX

// Rule ID: 1,954 - Active Debug Code
// Description: In addition to debug statements potentially logging data excessively, debug statements also contribute to longer transactions and consume Apex CPU time even when debug logs are not being captured.
// TODO: Provide actual vulnerable code

// Rule ID: 1,955 - Improper Neutralization of Special Elements in Data Query Logic
// Description: If a dynamic query must be used,leverage nFORCE Query Builder. In other programming languages, the related flaw is known as SQL injection. Apex doesn't use SQL, but uses its own database query language, SOQL. SOQL is much simpler and more limited in functionality than SQL. The risks are much lower for SOQL injection than for SQL injection, but the attacks are nearly identical to traditional SQL injection. SQL/SOQL injection takes user-supplied input and uses those values in a dynamic SOQL query. If the input isn't validated, it can include SOQL commands that effectively modify the SOQL statement and trick the application into performing unintended commands.
// TODO: Provide actual vulnerable code

// Rule ID: 1,956 - Improper Neutralization of Special Elements in Data Query Logic
// Description: If a dynamic query must be used,leverage nFORCE Query Builder. In other programming languages, the related flaw is known as SQL injection. Apex doesn't use SQL, but uses its own database query language, SOQL. SOQL is much simpler and more limited in functionality than SQL. The risks are much lower for SOQL injection than for SQL injection, but the attacks are nearly identical to traditional SQL injection. SQL/SOQL injection takes user-supplied input and uses those values in a dynamic SOQL query. If the input isn't validated, it can include SOQL commands that effectively modify the SOQL statement and trick the application into performing unintended commands.
// TODO: Provide actual vulnerable code

// Rule ID: 1,957 - Use of Hard-coded Cryptographic Key
// Description: The rule makes sure you are using randomly generated IVs and keys for Crypto calls. Hard-coding these values greatly compromises the security of encrypted data.
// TODO: Provide actual vulnerable code

// Rule ID: 1,958 - Cross-Site Request Forgery (CSRF)
// Description: Having DML operations in Apex class constructor or initializers can have unexpected side effects: By just accessing a page, the DML statements would be executed and the database would be modified. Just querying the database is permitted.
// TODO: Provide actual vulnerable code

// Rule ID: 1,959 - Incorrect Authorization
// Description: Native Salesforce DML operations execute in system context, ignoring the current user's permissions, field-level security, organization-wide defaults, position in the role hierarchy, and sharing rules. Be mindful when using native Salesforce DML operations.
// TODO: Provide actual vulnerable code

// Rule ID: 1,960 - Inclusion of Sensitive Information in Source Code
// Description: Named Credentials (and callout endpoints) should be used instead of hard-coding credentials. 1. Hard-coded credentials are hard to maintain when mixed in with application code. 2. It is particularly hard to update hard-coded credentials when they are used amongst different classes. 3. Granting a developer access to the codebase means granting knowledge of credentials, and thus keeping a two-level access is not possible. 4. Using different credentials for different environments is troublesome and error-prone.
// TODO: Provide actual vulnerable code

// Rule ID: 1,961 - Cleartext Transmission of Sensitive Information
// Description: The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.
// TODO: Provide actual vulnerable code

// Rule ID: 1,962 - Inclusion of Sensitive Information in Source Code
// Description: Named Credentials (and callout endpoints) should be used instead of hard-coding credentials. 1. Hard-coded credentials are hard to maintain when mixed in with application code. 2. It is particularly hard to update hard-coded credentials when they are used amongst different classes. 3. Granting a developer access to the codebase means granting knowledge of credentials, and thus keeping a two-level access is not possible. 4. Using different credentials for different environments is troublesome and error-prone.
// TODO: Provide actual vulnerable code

// Rule ID: 1,963 - Improper Access Control
// Description: Every Apex class should have an explicit sharing mode declared. Use the `with sharing` or `without sharing` keywords on a class to specify whether sharing rules must be enforced. Use the `inherited sharing` keyword on an Apex class to run the class in the sharing mode of the class that called it.
// TODO: Provide actual vulnerable code

