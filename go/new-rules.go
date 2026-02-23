package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"gorm.io/gorm"
)

// Mock global database instance for the GORM example
var db *gorm.DB

type User struct {
	ID       uint
	Username string
}

// 1. SYM_GO_0079: OS Command Injection
func commandInjectionHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")

	// VULNERABLE: Passes user input directly into exec.Command
	cmd := exec.Command("ping", "-c", "4", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Command execution failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// 2. SYM_GO_0080: SQL Injection in GORM
func sqlInjectionHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	var user User

	// VULNERABLE: Dynamic SQL query constructed via fmt.Sprintf in a Where clause
	query := fmt.Sprintf("username = '%s'", username)
	db.Where(query).First(&user)

	fmt.Fprintf(w, "Fetched user: %s", user.Username)
}

// 3. SYM_GO_0082: Path Traversal
func pathTraversalHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	baseDir := "/var/www/uploads"

	// VULNERABLE: Dynamic file path constructed with user input and read directly
	targetPath := filepath.Join(baseDir, filename)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Write(data)
}

// 4. SYM_GO_0089: Memory Exhaustion / DoS
func memoryExhaustionHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Reading unbounded HTTP request stream directly into memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Processed payload of size: %d", len(body))
}

// 5. SYM_GO_0090: Zip Slip / Arbitrary File Overwrite
func zipSlipHandler(w http.ResponseWriter, r *http.Request) {
	// Simulating opening an uploaded zip file
	zr, err := zip.OpenReader("uploaded_payload.zip")
	if err != nil {
		http.Error(w, "Failed to open zip", http.StatusInternalServerError)
		return
	}
	defer zr.Close()

	destDir := "/tmp/extracted_files"

	// VULNERABLE: Blindly trusting f.Name and joining it to the destination path
	for _, f := range zr.File {
		targetPath := filepath.Join(destDir, f.Name)

		if !f.FileInfo().IsDir() {
			// Simulating extraction without validation bounds check
			os.WriteFile(targetPath, []byte("dummy data"), 0644)
		}
	}

	w.Write([]byte("Extraction complete"))
}

func main() {
	http.HandleFunc("/ping", commandInjectionHandler)
	http.HandleFunc("/user", sqlInjectionHandler)
	http.HandleFunc("/download", pathTraversalHandler)
	http.HandleFunc("/upload", memoryExhaustionHandler)
	http.HandleFunc("/extract", zipSlipHandler)

	fmt.Println("Vulnerable server starting on :8080...")
	http.ListenAndServe(":8080", nil)
}

func sqlInjectionRawHandler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("role")
	var users []User

	// VULNERABLE: SYM_GO_0080 is triggered here because user input 
	// is concatenated directly into a Raw SQL query string using the '+' operator.
	// An attacker could pass "admin' OR 1=1 --" to bypass intended logic.
	db.Raw("SELECT * FROM users WHERE role = '" + userInput + "'").Scan(&users)

	fmt.Fprintf(w, "Found %d users", len(users))
}