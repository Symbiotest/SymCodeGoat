(ns vulnerable.core
  (:require [clojure.java.jdbc :as jdbc]
            [clojure.string :as str]
            [clojure.java.shell :as shell]
            [clojure.java.io :as io]
            [ring.util.response :as ring-resp]
            [ring.middleware.params :refer [wrap-params]]
            [ring.adapter.jetty :as jetty]
            [cheshire.core :as json]
            [environ.core :refer [env]]
            [clojure.data.codec.base64 :as b64]
            [clojure.walk :as walk]))

;; 1. SQL Injection
defn vulnerable-sql [db user-id]
  (jdbc/query db [(str "SELECT * FROM users WHERE id = '" user-id "'")]))

;; 2. Command Injection
defn vulnerable-command [user-input]
  (shell/sh "sh" "-c" (str "echo " user-input)))

;; 3. Path Traversal
defn vulnerable-file-read [filename]
  (slurp (str "/home/user/" filename)))

;; 4. Insecure Deserialization
defn vulnerable-deserialize [serialized]
  (read-string serialized)) ; read-string is dangerous with untrusted input

;; 5. XSS in Web Application
defn vulnerable-xss-handler [request]
  (let [user-input (get-in request [:params "input"])]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (str "<div>" user-input "</div>")}))

;; 6. SSRF (Server-Side Request Forgery)
(defn vulnerable-ssrf [url]
  (slurp url))

;; 7. Hardcoded Secrets
(def api-key "12345-67890-abcdef")
(def db-password "s3cr3tP@ssw0rd")

;; 8. Insecure Randomness
(defn insecure-token []
  (str (rand-int 10000))) ; Not cryptographically secure

;; 9. Security Misconfiguration
(def app-routes
  ["/admin" {:get (fn [req] {:status 200 :body "Admin Panel"})}])

;; 10. Insecure Direct Object Reference
defn get-user-file [user-id]
  (str "/userdata/" user-id ".txt"))

;; 11. No Input Validation
defn process-user-data [data]
  (eval (read-string data))) ; Extremely dangerous!

;; 12. Insecure Cryptography
defn weak-encrypt [data]
  (let [key "weakkey123"
        key-bytes (.getBytes key "UTF-8")
        data-bytes (.getBytes data "UTF-8")]
    (b64/encode (map bit-xor data-bytes (cycle key-bytes)))))

;; 13. XML External Entity (XXE)
(defn parse-xml [xml-str]
  (let [factory (javax.xml.parsers.SAXParserFactory/newInstance)]
    (.setFeature factory "http://apache.org/xml/features/disallow-doctype-decl" false)
    (-> (.newSAXParser factory)
        (.parse (java.io.ByteArrayInputStream. (.getBytes xml-str)) 
                (org.xml.sax.helpers.DefaultHandler.)))))

;; 14. Insecure File Upload
defn save-uploaded-file [file-part]
  (let [filename (:filename file-part)
        temp-file (java.io.File. (str "uploads/" filename))]
    (io/copy (:tempfile file-part) temp-file)
    (.getAbsolutePath temp-file)))

;; 15. Insecure Cookie Handling
defn set-insecure-cookie [response]
  (assoc-in response [:cookies "sessionid"] 
           {:value "12345" 
            :http-only false
            :secure false
            :max-age 31536000}))

;; 16. No Rate Limiting
defn process-request [request]
  ;; Process request without rate limiting
  {:status 200 :body "Request processed"})

;; 17. Information Exposure Through Error Messages
defn get-user [user-id]
  (try
    (jdbc/query db ["SELECT * FROM users WHERE id = ?" user-id])
    (catch Exception e
      {:status 500 :body (str "Error: " (.getMessage e))})))

;; 18. Using Components with Known Vulnerabilities
;; Example: Using an outdated library version

;; 19. Missing Function Level Access Control
defn admin-action [request]
  (if (= (:role (:session request)) "admin")
    {:status 200 :body "Admin action performed"}
    {:status 200 :body "Action performed"}))

;; 20. Insecure Redirects and Forwards
defn redirect-user [request]
  (let [target (get-in request [:params "target"])]
    (ring-resp/redirect target))) ; Open redirect vulnerability

;; Example web server setup
(def app
  (-> (fn [request]
        (vulnerable-xss-handler request))
      wrap-params))

(defn -main [& args]
  (jetty/run-jetty app {:port 3000})
  (println "Server running on port 3000"))

;; Example usage in REPL:
(comment
  ;; SQL Injection
  (vulnerable-sql "1' OR '1'='1")
  
  ;; Command Injection
  (vulnerable-command "hello; rm -rf /")
  
  ;; Path Traversal
  (vulnerable-file-read "../../etc/passwd")
  
  ;; Insecure Deserialization
  (vulnerable-deserialize "#=(clojure.java.shell/sh \"rm\" \"-rf\" \"/\")")
  
  ;; Start the server
  (-main))
