package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

type Config struct {
	Database struct {
		Host     string
		Port     string
		Name     string
		User     string
		Password string
	}
	Server struct {
		Port     string
		LogLevel string
	}
	API struct {
		Key    string
		Secret string
	}
}

type UserService struct {
	db     *sql.DB
	config *Config
}

func NewUserService(config *Config) (*UserService, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		config.Database.User,
		config.Database.Password,
		config.Database.Host,
		config.Database.Port,
		config.Database.Name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	return &UserService{
		db:     db,
		config: config,
	}, nil
}

func (s *UserService) GetUserProfile(username string) (map[string]interface{}, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))

	for i := range columns {
		valuePtrs[i] = &values[i]
	}

	if rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		result := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				result[col] = string(b)
			} else {
				result[col] = val
			}
		}
		return result, nil
	}

	return nil, fmt.Errorf("user not found")
}

func (s *UserService) RenderUserProfile(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := s.GetUserProfile(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>User Profile</title>
	</head>
	<body>
		<h1>Welcome, {{.Username}}!</h1>
		<div id="user-data">
			<p>Email: {{.Email}}</p>
			<p>Last Login: {{.LastLogin}}</p>
		</div>
	</body>
	</html>`

	t, err := template.New("profile").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, user); err != nil {
		log.Printf("Error executing template: %v", err)
	}
}

func (s *UserService) ProcessUserData(data []byte) (map[string]interface{}, error) {
	var userData map[string]interface{}
	if err := json.Unmarshal(data, &userData); err != nil {
		return nil, err
	}
	return userData, nil
}

func (s *UserService) LoadUserFile(userID, filename string) ([]byte, error) {
	basePath := "/var/www/user_files"
	filePath := filepath.Join(basePath, userID, filename)
	return os.ReadFile(filePath)
}

func (s *UserService) ExecuteSystemCommand(cmdStr string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *UserService) FetchExternalResource(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (s *UserService) LogUserActivity(userID, activity string) {
	logFile := "/var/log/user_activity.log"
	logEntry := fmt.Sprintf("[%s] User %s: %s\n", 
		time.Now().Format(time.RFC3339), 
		userID, 
		activity)

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write to log file: %v", err)
	}
}

type UserPreferences struct {
	Theme             string   `json:"theme"`
	Notifications     bool     `json:"notifications"`
	FavoriteSearches []string `json:"favorite_searches"`
	CustomCSS        string   `json:"custom_css"`
}
	cmd := exec.Command("sh", "-c", "echo "+cmdString) // Command Injection
	output, _ := cmd.Output()
	fmt.Println(string(output))
}

// 6. Insecure Direct Object Reference
func vulnerableIDOR(userID string) string {
	return "/userdata/" + userID + ".txt" // Insecure Direct Object Reference
}

// 7. Security Misconfiguration
func vulnerableConfig() {
	// Disabling HTTP security headers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "")
		w.Header().Set("X-Frame-Options", "")
		w.Header().Set("X-XSS-Protection", "0")
	})
}

// 8. Using Components with Known Vulnerabilities
// Example: Using an outdated version of a library with known vulnerabilities

// 9. Insufficient Logging & Monitoring
func vulnerableLogging(input string) {
	log.Printf("Processing input: %s", input) // Insufficient Logging
}

// 10. Server-Side Request Forgery (SSRF)
func vulnerableSSRF(url string) {
	resp, _ := http.Get(url) // SSRF
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

// 11. Template Injection
func vulnerableTemplate(w http.ResponseWriter, r *http.Request) {
	tmpl := `Hello, {{.}}!`
	t, _ := template.New("test").Parse(tmpl)
	t.Execute(w, r.URL.Query().Get("name")) // Template Injection
}

// 12. Hardcoded Secrets
const (
	apiKey     = "hardcoded-api-key-12345" // Hardcoded Secret
	dbPassword = "s3cr3tP@ssw0rd"          // Hardcoded Secret
)

func main() {
	// Example usage
	db, _ := sql.Open("mysql", "user:password@/dbname")
	defer db.Close()

	http.HandleFunc("/xss", vulnerableXSS)
	http.HandleFunc("/template", vulnerableTemplate)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
