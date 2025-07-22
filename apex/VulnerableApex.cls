public with sharing class VulnerableApex {
    
    // 1. SOQL Injection
    public static List<SObject> vulnerableSOQL(String userId) {
        String query = 'SELECT Id, Name, Email FROM User WHERE Id = \'' + userId + '\'';
        return Database.query(query); // SOQL Injection
    }
    
    // 2. Cross-Site Scripting (XSS) in Visualforce
    public String userInput { get; set; }
    public String getUnsafeOutput() {
        return userInput; // XSS if not properly escaped in Visualforce
    }
    
    // 3. Insecure Direct Object Reference (IDOR)
    public static void updateContactEmail(String contactId, String newEmail) {
        Contact c = [SELECT Id, Email FROM Contact WHERE Id = :contactId];
        c.Email = newEmail;
        update c; // No CRUD/FLS check
    }
    
    // 4. Insecure Deserialization
    public static Object vulnerableDeserialization(String jsonData) {
        return JSON.deserializeUntyped(jsonData); // Insecure if not validated
    }
    
    // 5. Security Misconfiguration
    public static void logSensitiveData(String data) {
        // Debug logs might contain sensitive information
        System.debug('Processing data: ' + data);
        
        // Disabled sharing
        without sharing class InternalOps {
            public static void deleteAllContacts() {
                delete [SELECT Id FROM Contact];
            }
        }
    }
    
    // 6. Using Components with Known Vulnerabilities
    // Example: Using an outdated version of a managed package
    
    // 7. Insufficient Logging & Monitoring
    public static void logUserAction(String action) {
        System.debug('User action: ' + action); // Insufficient logging
    }
    
    // 8. Cross-Site Request Forgery (CSRF)
    // Note: Apex is generally protected against CSRF, but custom implementations might be vulnerable
    
    // 9. Insecure File Handling
    public static void processFile(Blob fileData, String fileName) {
        // No file type validation
        ContentVersion cv = new ContentVersion();
        cv.VersionData = fileData;
        cv.Title = fileName;
        cv.PathOnClient = fileName;
        insert cv;
    }
    
    // 10. Hardcoded Secrets
    private static final String API_KEY = '12345-67890-abcdef';
    private static final String DB_PASSWORD = 's3cr3tP@ssw0rd';
    
    // 11. Insecure Cryptography
    public static String encryptData(String data) {
        // Using weak encryption
        Blob cryptoKey = Crypto.generateAesKey(128);
        Blob encryptedData = Crypto.encryptWithManagedIV('AES128', cryptoKey, Blob.valueOf(data));
        return EncodingUtil.base64Encode(encryptedData);
    }
    
    // 12. No Rate Limiting
    @AuraEnabled
    public static void processBatchData(List<String> dataList) {
        // No limit on batch size
        for (String data : dataList) {
            // Process data
        }
    }
    
    // 13. Insecure Direct Object Reference (IDOR) - Visualforce Example
    public PageReference viewContact() {
        String contactId = ApexPages.currentPage().getParameters().get('id');
        // No check if user has access to this contact
        return new PageReference('/' + contactId);
    }
    
    // 14. Insecure DML in Loop
    public static void updateContacts(List<Contact> contacts) {
        for (Contact c : contacts) {
            // DML inside loop - bad practice
            update c;
        }
    }
    
    // 15. No CRUD/FLS Check
    public static List<Account> getAccounts() {
        // No CRUD/FLS check
        return [SELECT Id, Name, AnnualRevenue FROM Account];
    }
    
    // 16. Insecure Apex Sharing
    public static void shareRecord(Id recordId, Id userId) {
        // No validation on record access
        AccountShare accShare = new AccountShare();
        accShare.AccountId = recordId;
        accShare.UserOrGroupId = userId;
        accShare.AccountAccessLevel = 'Edit';
        accShare.OpportunityAccessLevel = 'Edit';
        insert accShare;
    }
    
    // 17. No Input Validation
    public static void createTask(String subject, String description) {
        // No input validation
        Task t = new Task(
            Subject = subject,
            Description = description,
            Status = 'Not Started',
            Priority = 'Normal'
        );
        insert t;
    }
    
    // 18. Insecure Apex REST Endpoint
    @HttpPost
    global static String processData(String jsonData) {
        // No validation of input
        Map<String, Object> data = (Map<String, Object>)JSON.deserializeUntyped(jsonData);
        return 'Processed: ' + data.get('name');
    }
    
    // 19. No Error Handling
    public static Decimal calculateDiscount(Decimal amount) {
        // No error handling for division by zero or null
        return amount / 0;
    }
    
    // 20. Insecure Session Management
    public static String getSessionInfo() {
        // Exposing session ID in logs or UI
        return UserInfo.getSessionId();
    }
}
