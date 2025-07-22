using System;
using System.Data.SqlClient;
using System.IO;
using System.Web;
using System.Xml;
using System.Diagnostics;

public class VulnerableExamples
{
    // 1. SQL Injection
    public void VulnerableSQL(string userInput)
    {
        string query = $"SELECT * FROM Users WHERE Username = '{userInput}'";
        using (SqlConnection connection = new SqlConnection("connection_string_here"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            command.ExecuteNonQuery(); // SQL Injection
        }
    }

    // 2. XSS
    public string VulnerableXSS(string userInput)
    {
        return $"<div>{userInput}</div>"; // XSS
    }

    // 3. Insecure Deserialization
    public object VulnerableDeserialization(byte[] data)
    {
        var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        using (var ms = new MemoryStream(data))
        {
            return formatter.Deserialize(ms); // Insecure Deserialization
        }
    }

    // 4. XXE (XML External Entity)
    public void VulnerableXXE(string xml)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.XmlResolver = new XmlUrlResolver(); // XXE
        xmlDoc.LoadXml(xml);
    }

    // 5. Path Traversal
    public string VulnerablePathTraversal(string filename)
    {
        return File.ReadAllText($"C:\\data\\{filename}"); // Path Traversal
    }

    // 6. Command Injection
    public void VulnerableCommandInjection(string input)
    {
        Process.Start("cmd.exe", $"/C echo {input}"); // Command Injection
    }

    // 7. Insecure Direct Object Reference
    public string VulnerableIDOR(string userId)
    {
        return $"/userdata/{userId}.txt"; // Insecure Direct Object Reference
    }

    // 8. Security Misconfiguration
    public void VulnerableConfig()
    {
        // Disabling security features
        System.Net.ServicePointManager.ServerCertificateValidationCallback += 
            (sender, cert, chain, sslPolicyErrors) => { return true; }; // Security Misconfiguration
    }

    // 9. Using Components with Known Vulnerabilities
    public void VulnerableDependency()
    {
        // Using Newtonsoft.Json 10.0.1 which has known vulnerabilities
        // Example: CVE-2021-24112
    }

    // 10. Insufficient Logging & Monitoring
    public void VulnerableLogging(string userInput)
    {
        Console.WriteLine($"User input: {userInput}"); // Insufficient Logging
    }

    // Bonus: Insecure Authentication
    public bool VulnerableAuthentication(string username, string password)
    {
        // Hardcoded credentials
        return username == "admin" && password == "admin123"; // Insecure Authentication
    }
}
