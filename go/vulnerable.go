package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	_ "github.com/go-sql-driver/mysql"
)

// 1. SQL Injection
func vulnerableSQL(db *sql.DB, username string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)
	rows, _ := db.Query(query) // SQL Injection
	defer rows.Close()
}

// 2. XSS
func vulnerableXSS(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("input")
	fmt.Fprintf(w, "<div>%s</div>", userInput) // XSS
}

// 3. Insecure Deserialization
// Note: Go's encoding/gob is generally safe, but custom unmarshaling can be vulnerable
type User struct {
	Name string
}

func (u *User) UnmarshalBinary(data []byte) error {
	// Custom unmarshal logic that could be vulnerable
	u.Name = string(data)
	return nil
}

// 4. Path Traversal
func vulnerablePathTraversal(filename string) {
	path := filepath.Join("/data/", filename)
	data, _ := ioutil.ReadFile(path) // Path Traversal
	fmt.Println(string(data))
}

// 5. Command Injection
func vulnerableCommandInjection(cmdString string) {
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
