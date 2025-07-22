(ns vulnerable.deserialization
  "Example of insecure deserialization in Clojure")

(require '[clojure.edn :as edn])
(import 'java.io.ObjectInputStream
        'java.io.ByteArrayInputStream
        'java.io.ByteArrayOutputStream
        'java.io.ObjectOutputStream
        'java.util.Base64)

;; VULNERABLE: Insecure deserialization using read-string with untrusted data
(defn unsafe-deserialize [serialized]
  (binding [*read-eval* true]  ; Dangerous: allows code execution during read
    (read-string serialized)))

;; Secure alternative: Use safe reader without evaluation
(defn safe-deserialize [serialized]
  (edn/read-string 
    {:readers *data-readers*  ; Only use safe, predefined readers
     :default (fn [tag value] value)}  ; Don't execute code
    serialized))

;; Example of a potentially malicious payload
(def malicious-payload 
  "#=(clojure.java.shell/sh \"sh\" \"-c\" \"echo 'malicious code executed' > /tmp/hacked\")")

;; Example usage
(comment
  ;; Dangerous - will execute arbitrary code
  (try 
    (unsafe-deserialize malicious-payload)
    (catch Exception e (str "Caught: " (.getMessage e))))
  
  ;; Safe - will not execute code
  (try 
    (safe-deserialize malicious-payload)
    (catch Exception e (str "Caught: " (.getMessage e))))
  
  ;; Example with Java deserialization (also dangerous)
  (defn serialize [obj]
    (let [baos (ByteArrayOutputStream.)
          oos (ObjectOutputStream. baos)]
      (.writeObject oos obj)
      (.toByteArray baos)))
      
  (defn deserialize [bytes]
    (let [bais (ByteArrayInputStream. bytes)
          ois (ObjectInputStream. bais)]
      (.readObject ois)))
  
  ;; Always validate and sanitize input before deserialization
  (defn safe-java-deserialize [bytes]
    (when (trusted-source? bytes)  ; Implement this check based on your app
      (deserialize bytes))))
