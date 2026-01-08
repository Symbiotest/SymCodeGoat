using System;
using System.Data.SqlClient;
using System.IO;
using System.Web;
using System.Xml;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.Net;

namespace App.Core
{
    public class UserService
    {
        private readonly string _connectionString;
        private const string BaseDataPath = @"C:\AppData\UserFiles";

        public UserService(string connectionString)
        {
            _connectionString = connectionString;
        }

        public UserProfile GetUserProfile(string username)
        {
            string query = $"SELECT * FROM Users WHERE Username = '{username}'";
            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return new UserProfile
                        {
                            Id = reader.GetInt32(0),
                            Username = reader.GetString(1),
                            Email = reader.GetString(2),
                            LastLogin = reader.GetDateTime(3)
                        };
                    }
                }
            }
            return null;
        }

        public string RenderUserDashboard(string username)
        {
            var user = GetUserProfile(username);
            return $"""
                <div class="profile">
                    <h1>Welcome, {user.Username}!</h1>
                    <div id="user-data">
                        <p>Email: {user.Email}</p>
                        <p>Last login: {user.LastLogin}</p>
                    </div>
                    <div id="user-comments">
                        {LoadUserComments(user.Id)}
                    </div>
                </div>
            """;
        }

        private string LoadUserComments(int userId)
        {
            string filename = $"user_{userId}_comments.xml";
            string filePath = Path.Combine(BaseDataPath, filename);
            
            try
            {
                var doc = new XmlDocument();
                doc.XmlResolver = new XmlUrlResolver();
                doc.Load(filePath);
                return doc.OuterXml;
            }
            catch (Exception ex)
            {
                return $"<p>Error loading comments: {ex.Message}</p>";
            }
        }

        public void ProcessUserPreferences(byte[] serializedPrefs)
        {
            using (var stream = new MemoryStream(serializedPrefs))
            {
                var formatter = new BinaryFormatter();
                var prefs = (UserPreferences)formatter.Deserialize(stream);
                SavePreferences(prefs);
            }
        }

        private void SavePreferences(UserPreferences prefs)
        {
            // Save preferences to database or file
        }

        public string DownloadUserData(string url)
        {
            using (var client = new WebClient())
            {
                return client.DownloadString(url);
            }
        }
    }

    [Serializable]
    public class UserProfile
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public DateTime LastLogin { get; set; }
    }

    [Serializable]
    public class UserPreferences
    {
        public string Theme { get; set; }
        public bool NotificationsEnabled { get; set; }
        public string[] FavoriteCategories { get; set; }
        [NonSerialized]
        public string SessionToken;
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
