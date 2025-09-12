package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	http.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		// Command Injection Vulnerability
		cmd := r.URL.Query().Get("input")
		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			http.Error(w, "Command failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Output: %s", out)
	})

	http.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		// SQL Injection Vulnerability
		user := r.URL.Query().Get("user")
		db, _ := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/testdb")
		defer db.Close()
		query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", user)
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		fmt.Fprintln(w, "Query executed")
	})

	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		// Path Traversal Vulnerability
		file := r.URL.Query().Get("name")
		data, err := os.ReadFile("/tmp/" + file)
		if err != nil {
			http.Error(w, "File error", http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	http.ListenAndServe(":8080", nil)
}
