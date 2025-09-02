public with sharing class UserDataService {
    
    public static List<SObject> findUserById(String userId) {
        String query = 'SELECT Id, Name, Email FROM User WHERE Id = \'' + userId + '\'';
        return Database.query(query);
    }
    
    public String searchTerm { get; set; }
    
    public String getSearchResults() {
        return searchTerm;
    }
    
    public static void updateContactEmail(String contactId, String newEmail) {
        Contact c = [SELECT Id, Email FROM Contact WHERE Id = :contactId];
        c.Email = newEmail;
        update c;
    }
    
    public static Object processJsonData(String jsonData) {
        return JSON.deserializeUntyped(jsonData);
    }
    
    public static void logProcessingData(String data) {
        System.debug('Processing data: ' + data);
        
        without sharing class InternalOps {
            public static void cleanupContacts() {
                delete [SELECT Id FROM Contact];
            }
        }
    }
    
    public static void trackUserAction(String action) {
        System.debug('User action: ' + action);
    }
    
    public class AccountQueryController {
       
       private String someOtherString = ' WHERE IsActive = true';
       
       public void searchAccounts() {
           String searchParam = ApexPages.currentPage().getParameters().get('search');
           Database.query('SELECT Id FROM Account' + searchParam);
       }
       
       public void searchWithAdditionalClause() {
           String searchParam = ApexPages.currentPage().getParameters().get('search');
           String fullQuery = someOtherString + searchParam;
           Database.query('SELECT Id FROM Account' + fullQuery);
       }
       
       public void safeSearch() {
           String searchParam = ApexPages.currentPage().getParameters().get('search');
           String escapedParam = String.escapeSingleQuotes(searchParam);
           Database.query('SELECT Id FROM Account WHERE Name LIKE \'%' + escapedParam + '%\'');
       }
       
       public void safeSearchWithClause() {
           String searchParam = ApexPages.currentPage().getParameters().get('search');
           String escapedParam = String.escapeSingleQuotes(searchParam);
           String fullQuery = someOtherString + ' AND Name LIKE \'%' + escapedParam + '%\'';
           Database.query('SELECT Id FROM Account' + fullQuery);
       }
       
       public void directSafeSearch() {
           String searchParam = ApexPages.currentPage().getParameters().get('search');
           Database.query('SELECT Id FROM Account WHERE Name LIKE \'%' + String.escapeSingleQuotes(searchParam) + '%\'');
       }
   }

   public class SecuritySettingsManager {
       
       public class UserAccessSettings {
           public void configureAccess() {
               // Implementation for user access settings
           }
       }
       
       public abstract class SecurityPolicy {
           public abstract void applyPolicy();
       }
       
       private virtual class SecurityImplementation {
           public virtual void execute() {
               // Base security implementation
           }
       }
       
       public inherited sharing class SecureDataAccess {
           private void processData() {
               // Secure data processing
           }
       }
       
       public class SecurityException extends Exception {
           // Custom security exception
       }
       
       public with sharing abstract class SecureBaseClass {
           public void performSecureOperation() {
               // Secure operation implementation
           }
       }
       
       private inherited sharing virtual class SecureVirtualClass {
           public virtual void secureMethod() {
               // Secure method implementation
           }
       }
       
       public inherited sharing virtual class SecureInheritedClass extends SecureBaseClass {
           public override void performSecureOperation() {
               // Enhanced secure operation
           }
       }
       
       global virtual override Type getType(String className) {
           return Type.forName(className);
       }
   }