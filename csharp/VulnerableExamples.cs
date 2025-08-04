using System;
using System.Data.SqlClient;
using System.IO;
using System.Web;
using System.Xml;
using System.Diagnostics;

public class VulnerableExamples
{

    public void VulnerableSQL(string userInput)
    {
        // Use parameterized query to prevent SQL injection
        string query = "SELECT * FROM Users WHERE Username = @Username";
        using (SqlConnection connection = new SqlConnection("connection_string_here"))
        {
            connection.Open();
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                // Add parameter to prevent injection
                command.Parameters.AddWithValue("@Username", userInput);
                command.ExecuteNonQuery();
            }
        }
    }


    public string VulnerableXSS(string userInput)
    {
        return $"<div>{userInput}</div>"; 
    }


    public object VulnerableDeserialization(byte[] data)
    {
        var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        using (var ms = new MemoryStream(data))
        {
            return formatter.Deserialize(ms); 
        }
    }


    public void VulnerableXXE(string xml)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.XmlResolver = new XmlUrlResolver();
        xmlDoc.LoadXml(xml);  // nosymbiotic: SYM_CS_0024 -fp 
    }


    public string VulnerablePathTraversal(string filename)
    {
        return File.ReadAllText($"C:\\data\\{filename}"); /
    }


    public void VulnerableCommandInjection(string input)
    {
        Process.Start("cmd.exe", $"/C echo {input}"); 
    }

    public string VulnerableIDOR(string userId)
    {
        return $"/userdata/{userId}.txt"; 
    }


    public void VulnerableConfig()
    {

        System.Net.ServicePointManager.ServerCertificateValidationCallback += 
            (sender, cert, chain, sslPolicyErrors) => { return true; }; 
    }


    public void VulnerableLogging(string userInput)
    {
        Console.WriteLine($"User input: {userInput}"); 
    }


    public bool VulnerableAuthentication(string username, string password)
    {

        return username == "admin" && password == "admin123"; 
    }
}
