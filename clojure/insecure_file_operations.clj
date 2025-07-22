(ns vulnerable.files
  "Examples of secure and insecure file operations in Clojure")

(require '[clojure.java.io :as io])
(import '[java.nio.file Paths Path Paths Paths Paths])

;; VULNERABLE: Reading files with user-controlled paths without validation
defn read-file-insecure [user-path]
  (slurp user-path))  ; Directly using user input to read files

;; VULNERABLE: Writing files with user-controlled paths
defn write-file-insecure [user-path content]
  (spit user-path content))

;; Secure version with path validation
defn sanitize-path [base-dir user-path]
  (let [base-path (.toRealPath (Paths/get base-dir (make-array String 0)))
        file-path (.toAbsolutePath (Paths/get user-path (make-array String 0)))
        normalized-path (.normalize file-path)]
    (when (not (.startsWith normalized-path base-path))
      (throw (SecurityException. "Access denied: Path traversal attempt")))
    (.toString normalized-path)))

;; Secure file reading
defn read-file-secure [base-dir user-path]
  (let [safe-path (sanitize-path base-dir user-path)]
    (slurp safe-path)))

;; Secure file writing
defn write-file-secure [base-dir user-path content]
  (let [safe-path (sanitize-path base-dir user-path)]
    (spit safe-path content)))

;; Example of secure file upload handling
defn handle-file-upload [upload-dir filename content]
  (let [upload-path (Paths/get upload-dir (make-array String 0))
        safe-filename (-> filename
                         (clojure.string/replace #"[^a-zA-Z0-9._-]" "")  ; Remove special chars
                         (clojure.string/lower-case))
        safe-path (sanitize-path upload-dir safe-filename)]
    (spit safe-path content)
    safe-path))

;; Example usage
(comment
  ;; Insecure usage (vulnerable to path traversal)
  (read-file-insecure "/etc/passwd")  ; Direct access to system files
  (write-file-insecure "/tmp/important" "malicious content")
  
  ;; Secure usage
  (def base-dir "/var/www/uploads")
  
  ;; These will work
  (read-file-secure base-dir "report.pdf")
  (write-file-secure base-dir "report.pdf" "PDF content...")
  
  ;; These will throw SecurityException
  (read-file-secure base-dir "../../etc/passwd")
  (write-file-secure base-dir "/etc/passwd" "malicious content")
  
  ;; File upload example
  (handle-file-upload "/var/www/uploads" "../../malicious.php" "<?php system($_GET['cmd']); ?>"))
  ;; The above will be sanitized to a safe filename within the upload directory
