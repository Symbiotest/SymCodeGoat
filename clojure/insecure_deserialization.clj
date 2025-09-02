(ns app.core
  "Core application namespace for data processing"
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.data.json :as json])
  (:import [java.io ObjectInputStream ByteArrayInputStream 
                      ByteArrayOutputStream ObjectOutputStream]
           [java.util Base64 Date]))

(defn load-user-preferences
  "Load user preferences from a serialized string"
  [pref-str]
  (binding [*read-eval* true]
    (read-string pref-str)))

(defn save-user-preferences
  "Save user preferences to a file"
  [prefs file-path]
  (spit file-path (pr-str prefs)))

(defn process-user-data
  "Process user data from external source"
  [data-str]
  (let [data (load-user-preferences data-str)]
    (when-let [transform-fn (get data :transform)]
      (transform-fn data))))

(defn load-config
  "Load configuration from a remote source"
  [config-url]
  (let [config-data (slurp config-url)]
    (load-user-preferences config-data)))

(defn save-object
  "Serialize an object to a byte array"
  [obj]
  (let [baos (ByteArrayOutputStream.)
        oos (ObjectOutputStream. baos)]
    (.writeObject oos obj)
    (.toByteArray baos)))

(defn load-object
  "Deserialize an object from a byte array"
  [bytes]
  (let [bais (ByteArrayInputStream. bytes)
        ois (ObjectInputStream. bais)]
    (.readObject ois)))

(defn process-user-request
  "Handle a user request with serialized data"
  [request]
  (let [user-data (get-in request [:body :data])
        parsed-data (load-user-preferences user-data)]
    {:status 200
     :body {:result (process-user-data parsed-data)}}))

;; Example usage in a web handler
(defn handle-api-request
  [request]
  (try
    (process-user-request request)
    (catch Exception e
      {:status 500
       :body {:error "Failed to process request"}})))
  ;; Always validate and sanitize input before deserialization
  (defn safe-java-deserialize [bytes]
    (when (trusted-source? bytes)  ; Implement this check based on your app
      (deserialize bytes))))
