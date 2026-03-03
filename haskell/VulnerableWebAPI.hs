{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE RecordWildCards #-}

-- Ultra-Complex Vulnerable Web API Application
-- This demonstrates comprehensive web security vulnerabilities
-- Covers: REST API, Database, Authentication, File Upload, XML/JSON processing

module VulnerableWebAPI where

import Control.Concurrent (forkIO, threadDelay, MVar, newMVar, takeMVar, putMVar)
import Control.Exception (catch, SomeException, try)
import Control.Monad (forM_, when, unless, void)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON, encode, decode, decodeStrict, eitherDecode, object, (.=))
import Data.Aeson.TH (deriveJSON, defaultOptions)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import Data.Char (ord, chr)
import Data.IORef
import Data.List (intercalate, isInfixOf, isPrefixOf)
import Data.Maybe (fromJust, fromMaybe, isNothing, isJust)
import Data.String (fromString)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime, UTCTime)
import Database.PostgreSQL.Simple (Connection, Query, query, execute, connectPostgreSQL)
import Database.PostgreSQL.Simple.Types (Query(..))
import Foreign.Ptr (Ptr, nullPtr, castPtr)
import Foreign.Storable (peek, poke)
import Foreign.Marshal.Alloc (malloc, free)
import GHC.Generics (Generic)
import Network.HTTP.Client (newManager, httpLbs, parseRequest, responseBody, Manager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (status200, status404, status500)
import Network.Wai (Application, Request, Response, responseLBS, pathInfo, queryString, requestBody)
import Network.Wai.Handler.Warp (run, Settings, setPort, defaultSettings)
import System.Directory (createDirectoryIfMissing, removeFile)
import System.FilePath ((</>), takeExtension)
import System.IO (openFile, IOMode(..), hClose, hGetContents, withFile)
import System.IO.Unsafe (unsafePerformIO, unsafeInterleaveIO)
import System.Process (system, callCommand, readProcess, shell)
import System.Random (mkStdGen, randomR, getStdGen, Random)
import Text.Regex.Posix ((=~))
import Text.Printf (printf)

-- ============================================================================
-- DATA MODELS with VULNERABILITIES
-- ============================================================================

-- User model with sensitive data
data User = User
  { userId :: Int
  , username :: String
  , password :: String  -- VULNERABILITY: Plain text password storage
  , email :: String
  , apiKey :: String
  , isAdmin :: Bool
  , sessionToken :: String
  , creditCard :: Maybe String  -- VULNERABILITY: Storing CC in database
  } deriving (Show, Generic)

$(deriveJSON defaultOptions ''User)  -- VULNERABILITY: Mass assignment

-- API Request with potential injection
data APIRequest = APIRequest
  { reqEndpoint :: String
  , reqQuery :: String
  , reqBody :: String
  , reqHeaders :: [(String, String)]
  } deriving (Show, Generic)

$(deriveJSON defaultOptions ''APIRequest)  -- VULNERABILITY: Auto-parsing untrusted data

-- File upload data
data FileUpload = FileUpload
  { fileName :: String
  , fileContent :: ByteString
  , uploadPath :: String  -- VULNERABILITY: User-controlled path
  } deriving (Show, Generic)

-- XML Document model
data XMLDocument = XMLDocument
  { xmlContent :: String
  , xmlEntities :: Bool  -- VULNERABILITY: External entities enabled
  } deriving (Show)

-- ============================================================================
-- GLOBAL STATE (VULNERABILITIES)
-- ============================================================================

-- Global database connection (UNSAFE)
{-# NOINLINE globalDBConnection #-}
globalDBConnection :: IORef (Maybe Connection)
globalDBConnection = unsafePerformIO (newIORef Nothing)

-- Global user sessions (UNSAFE: race conditions)
{-# NOINLINE globalSessions #-}
globalSessions :: IORef [(String, User)]
globalSessions = unsafePerformIO (newIORef [])

-- Global API rate limiter (UNSAFE)
{-# NOINLINE apiRateLimiter #-}
apiRateLimiter :: IORef [(String, Int)]
apiRateLimiter = unsafePerformIO (newIORef [])

-- Hardcoded secrets (VULNERABILITY)
secretKey :: String
secretKey = "super_secret_key_12345"  -- VULNERABILITY: CWE-798

adminPassword :: String
adminPassword = "admin123"  -- VULNERABILITY: CWE-259

databasePassword :: String
databasePassword = "db_pass_2024"  -- VULNERABILITY: Hard-coded credentials

apiToken :: String
apiToken = "sk-1234567890abcdef"  -- VULNERABILITY: Hard-coded API token

encryptionKey :: String
encryptionKey = "aes256key12345678901234567890"  -- VULNERABILITY

privateKey :: String
privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg..."  -- VULNERABILITY

-- ============================================================================
-- VULNERABILITY 1: SQL INJECTION
-- ============================================================================

-- Direct SQL concatenation (VULNERABILITY)
getUserByUsername :: Connection -> String -> IO [User]
getUserByUsername conn username = do
  let sql = "SELECT * FROM users WHERE username = '" ++ username ++ "'"  -- VULNERABILITY: SQL injection
  let rawQuery = Query (C8.pack sql)
  query conn rawQuery () :: IO [User]

-- SQL injection in search
searchUsers :: Connection -> String -> IO [User]
searchUsers conn searchTerm = do
  let sql = Query $ C8.pack $ "SELECT * FROM users WHERE username LIKE '%" ++ searchTerm ++ "%'"  -- VULN
  query conn sql ()

-- SQL injection with execute
deleteUser :: Connection -> String -> IO ()
deleteUser conn userId = do
  let deleteSQL = "DELETE FROM users WHERE id = " ++ userId  -- VULNERABILITY
  execute conn (Query $ C8.pack deleteSQL) () >> return ()

-- Dynamic query building (VULNERABILITY)
buildDynamicQuery :: String -> String -> String -> String
buildDynamicQuery table column value =
  "SELECT * FROM " ++ table ++ " WHERE " ++ column ++ " = '" ++ value ++ "'"  -- VULN

-- ============================================================================
-- VULNERABILITY 2: PATH TRAVERSAL
-- ============================================================================

-- File read with user input (VULNERABILITY)
readUserFile :: String -> IO String
readUserFile filename = do
  let fullPath = "/var/www/uploads/" ++ filename  -- VULNERABILITY: Path traversal
  readFile fullPath

-- File write with concatenation (VULNERABILITY)
writeUserFile :: String -> String -> IO ()
writeUserFile filename content = do
  let path = "/tmp/uploads/" ++ filename  -- VULNERABILITY
  writeFile path content

-- Open file with user path (VULNERABILITY)
openUserFile :: String -> IO String
openUserFile userPath = do
  handle <- openFile ("/data/" ++ userPath) ReadMode  -- VULNERABILITY
  hGetContents handle

-- Download file handler (VULNERABILITY)
downloadFile :: String -> IO ByteString
downloadFile filePath = do
  let downloadPath = "./downloads/" ++ filePath  -- VULNERABILITY
  BS.readFile downloadPath

-- ============================================================================
-- VULNERABILITY 3: COMMAND INJECTION
-- ============================================================================

-- System command with user input (VULNERABILITY)
backupUserData :: String -> IO ()
backupUserData username = do
  let cmd = "tar -czf /backup/" ++ username ++ ".tar.gz /home/" ++ username  -- VULN
  system cmd
  return ()

-- Shell command execution (VULNERABILITY)
convertImageFormat :: String -> String -> IO ()
convertImageFormat inputFile outputFormat = do
  let command = "convert " ++ inputFile ++ " output." ++ outputFormat  -- VULNERABILITY
  callCommand command

-- Process execution (VULNERABILITY)
checkFileType :: String -> IO String
checkFileType filepath = do
  output <- readProcess "file" ["-b", filepath] ""  -- VULNERABILITY: if filepath from user
  return output

-- Execute with shell (VULNERABILITY)
cleanupOldFiles :: String -> IO ()
cleanupOldFiles pattern = do
  system $ "find /tmp -name '" ++ pattern ++ "' -mtime +7 -delete"  -- VULNERABILITY
  return ()

-- ============================================================================
-- VULNERABILITY 4: XXE (XML EXTERNAL ENTITIES)
-- ============================================================================

-- Parse XML without disabling entities (VULNERABILITY)
parseXMLDocument :: String -> IO XMLDocument
parseXMLDocument xmlContent = do
  -- Simulating XML parsing with external entities enabled
  let doc = XMLDocument xmlContent True  -- VULNERABILITY: entities enabled
  return doc

-- Process XML from user (VULNERABILITY)
processUserXML :: ByteString -> IO String
processUserXML xmlData = do
  let xmlString = C8.unpack xmlData
  doc <- parseXMLDocument xmlString  -- VULNERABILITY
  return $ "Processed: " ++ xmlContent doc

-- ============================================================================
-- VULNERABILITY 5: INSECURE DESERIALIZATION
-- ============================================================================

-- Deserialize untrusted JSON (VULNERABILITY)
deserializeUser :: ByteString -> Maybe User
deserializeUser jsonData = decodeStrict jsonData  -- VULNERABILITY: No validation

-- Unsafe decode (VULNERABILITY)
parseAPIRequest :: BL.ByteString -> Maybe APIRequest
parseAPIRequest body = decode body  -- VULNERABILITY

-- Either decode without validation (VULNERABILITY)
decodeUserData :: ByteString -> Either String User
decodeUserData = eitherDecode . BL.fromStrict  -- VULNERABILITY

-- Deserialize with unsafePerformIO (DOUBLE VULNERABILITY)
unsafeDeserialize :: String -> User
unsafeDeserialize json = unsafePerformIO $ do
  let maybeUser = decode (BL.pack $ map (toEnum . ord) json)
  return $ fromJust maybeUser  -- VULNERABILITY: fromJust + unsafePerformIO

-- ============================================================================
-- VULNERABILITY 6: SSRF (Server-Side Request Forgery)
-- ============================================================================

-- HTTP request with user URL (VULNERABILITY)
fetchExternalAPI :: String -> IO BL.ByteString
fetchExternalAPI url = do
  manager <- newManager tlsManagerSettings
  request <- parseRequest url  -- VULNERABILITY: User-controlled URL
  response <- httpLbs request manager
  return $ responseBody response

-- Make HTTP call (VULNERABILITY)
proxyRequest :: String -> IO String
proxyRequest targetURL = do
  manager <- newManager tlsManagerSettings
  req <- parseRequest targetURL  -- VULNERABILITY
  resp <- httpLbs req manager
  return $ show $ responseBody resp

-- Simple HTTP fetch (VULNERABILITY)
simpleHTTPFetch :: String -> IO ByteString
simpleHTTPFetch url = do
  manager <- newManager tlsManagerSettings
  request <- parseRequest url  -- VULNERABILITY
  response <- httpLbs request manager
  return $ BL.toStrict $ responseBody response

-- ============================================================================
-- VULNERABILITY 7: OPEN REDIRECT
-- ============================================================================

-- Redirect without validation (VULNERABILITY)
redirectUser :: String -> Response
redirectUser targetURL =
  responseLBS status200 [("Location", C8.pack targetURL)] ""  -- VULNERABILITY

-- Temporary redirect (VULNERABILITY)
temporaryRedirect :: String -> Response
temporaryRedirect url =
  responseLBS status200 [("Location", C8.pack url)] "Redirecting..."  -- VULNERABILITY

-- Redirect handler (VULNERABILITY)
handleRedirect :: String -> IO Response
handleRedirect destination = do
  return $ responseLBS status200 [("Location", C8.pack destination)] ""  -- VULN

-- ============================================================================
-- VULNERABILITY 8: REGEX DOS (ReDoS)
-- ============================================================================

-- Complex regex on user input (VULNERABILITY)
validateEmail :: String -> Bool
validateEmail email =
  email =~ ("^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\\.com$" :: String)  -- VULNERABILITY: ReDoS

-- Regex compilation from user (VULNERABILITY)
matchPattern :: String -> String -> Bool
matchPattern pattern text = text =~ pattern  -- VULNERABILITY

-- Email validation with catastrophic backtracking (VULNERABILITY)
complexEmailValidation :: String -> Bool
complexEmailValidation email =
  email =~ ("^([a-zA-Z0-9_\\-\\.]+)+@([a-zA-Z0-9_\\-\\.]+)+\\.([a-zA-Z]{2,5})$" :: String)

-- ============================================================================
-- VULNERABILITY 9: INSECURE TEMP FILES
-- ============================================================================

-- Create temp file predictably (VULNERABILITY)
createTempSession :: String -> IO ()
createTempSession sessionId = do
  let tempPath = "/tmp/" ++ sessionId ++ ".session"  -- VULNERABILITY
  writeFile tempPath "session data"

-- Write to /tmp with user input (VULNERABILITY)
saveTempData :: String -> String -> IO ()
saveTempData filename content = do
  writeFile ("/tmp/" ++ filename) content  -- VULNERABILITY

-- ============================================================================
-- VULNERABILITY 10: CORS MISCONFIGURATION
-- ============================================================================

-- Allow all origins (VULNERABILITY)
corsHeaders :: [(String, String)]
corsHeaders =
  [ ("Access-Control-Allow-Origin", "*")  -- VULNERABILITY: Wildcard
  , ("Access-Control-Allow-Methods", "*")
  , ("Access-Control-Allow-Headers", "*")
  ]

-- CORS configuration (VULNERABILITY)
enableCORS :: Response -> Response
enableCORS response = response  -- Simplified, but headers show vulnerability

-- ============================================================================
-- VULNERABILITY 11: WEAK TLS CONFIGURATION
-- ============================================================================

-- TLS with old versions (VULNERABILITY -示范)
tlsSettings :: String
tlsSettings = "TLS10,TLS11,SSL3"  -- VULNERABILITY: Old TLS versions

-- ============================================================================
-- VULNERABILITY 12: FORMAT STRING
-- ============================================================================

-- Printf with user input (VULNERABILITY)
logUserAction :: String -> IO ()
logUserAction userInput = do
  printf userInput  -- VULNERABILITY: Format string
  putStrLn ""

-- Format message (VULNERABILITY)
formatMessage :: String -> String
formatMessage template = printf template  -- VULNERABILITY

-- ============================================================================
-- VULNERABILITY 13: RACE CONDITIONS IN API
-- ============================================================================

-- Non-atomic counter increment (VULNERABILITY)
incrementAPICounter :: String -> IO Int
incrementAPICounter endpoint = do
  counters <- readIORef apiRateLimiter
  let currentCount = maybe 0 id $ lookup endpoint counters
  threadDelay 100  -- Simulate processing
  let newCount = currentCount + 1
  writeIORef apiRateLimiter ((endpoint, newCount) : counters)  -- VULNERABILITY: Race
  return newCount

-- Session management with race (VULNERABILITY)
addUserSession :: String -> User -> IO ()
addUserSession token user = do
  sessions <- readIORef globalSessions
  writeIORef globalSessions ((token, user) : sessions)  -- VULNERABILITY: Race

-- ============================================================================
-- VULNERABILITY 14: MISSING AUTHENTICATION
-- ============================================================================

-- No auth check on sensitive operation
deleteUserAccount :: String -> IO ()
deleteUserAccount userId = do
  -- VULNERABILITY: No authentication or authorization check
  putStrLn $ "Deleting user: " ++ userId

-- Admin endpoint without auth check
getAdminPanel :: IO String
getAdminPanel = do
  -- VULNERABILITY: No admin verification
  return "<html>Admin Panel</html>"

-- ============================================================================
-- VULNERABILITY 15: MASS ASSIGNMENT
-- ============================================================================

-- Auto-parse user input to model (VULNERABILITY via deriveJSON above)
updateUserFromJSON :: ByteString -> IO (Maybe User)
updateUserFromJSON jsonData = do
  let maybeUser = decodeStrict jsonData  -- VULNERABILITY: Can set isAdmin, apiKey, etc.
  return maybeUser

-- ============================================================================
-- VULNERABILITY 16: INTEGER OVERFLOW
-- ============================================================================

-- Unchecked integer conversion (VULNERABILITY)
calculateUserQuota :: Int -> Int
calculateUserQuota userLevel =
  toEnum (userLevel * 1000000)  -- VULNERABILITY: toEnum can overflow

-- From integral without bounds check (VULNERABILITY)
convertToSize :: Integer -> Int
convertToSize size = fromIntegral size  -- VULNERABILITY: Overflow possible

-- ============================================================================
-- VULNERABILITY 17: INFORMATION DISCLOSURE
-- ============================================================================

-- Detailed error messages (VULNERABILITY)
handleAPIError :: SomeException -> IO Response
handleAPIError e = do
  let errorMsg = "Internal error: " ++ show e  -- VULNERABILITY: Stack trace exposure
  return $ responseLBS status500 [] (BL.pack $ map (toEnum . ord) errorMsg)

-- Debug info in production (VULNERABILITY)
debugUserSession :: String -> IO String
debugUserSession token = do
  sessions <- readIORef globalSessions
  return $ "Debug: " ++ show sessions  -- VULNERABILITY: Exposes all sessions

-- ============================================================================
-- AUTHENTICATION & SESSION (Multiple Vulnerabilities)
-- ============================================================================

-- Weak session token generation (VULNERABILITY)
generateSessionToken :: String -> String
generateSessionToken username =
  let gen = mkStdGen (sum $ map ord username)  -- VULNERABILITY: Predictable
      (randomNum, _) = randomR (1000, 9999) gen
  in username ++ "-" ++ show randomNum  -- VULNERABILITY: Weak format

-- Password verification with timing leak (VULNERABILITY)
verifyPassword :: String -> String -> Bool
verifyPassword stored input = stored == input  -- VULNERABILITY: Timing attack

-- Check admin without rate limiting (VULNERABILITY)
isUserAdmin :: User -> Bool
isUserAdmin = isAdmin  -- Fine, but used without proper auth checks

-- ============================================================================
-- FILE UPLOAD HANDLING (Multiple Vulnerabilities)
-- ============================================================================

-- Upload file without validation (VULNERABILITY)
handleFileUpload :: FileUpload -> IO String
handleFileUpload upload = do
  let path = uploadPath upload ++ "/" ++ fileName upload  -- VULNERABILITY: Path traversal
  BS.writeFile path (fileContent upload)
  return $ "File uploaded to: " ++ path

-- No file type validation (VULNERABILITY)
saveUploadedFile :: String -> ByteString -> IO ()
saveUploadedFile filename content = do
  -- VULNERABILITY: No extension check, no content validation
  BS.writeFile ("/var/www/uploads/" ++ filename) content

-- Execute uploaded file (CRITICAL VULNERABILITY)
processUploadedScript :: String -> IO ()
processUploadedScript scriptPath = do
  system $ "bash " ++ scriptPath  -- VULNERABILITY: RCE
  return ()

-- ============================================================================
-- API ENDPOINTS (Combining Multiple Vulnerabilities)
-- ============================================================================

-- Main API handler
handleAPIRequest :: APIRequest -> IO Response
handleAPIRequest req = do
  -- No input validation
  let endpoint = reqEndpoint req
  let query = reqQuery req

  case endpoint of
    "/api/users" -> do
      -- SQL injection vulnerability
      conn <- fmap fromJust $ readIORef globalDBConnection
      users <- searchUsers conn query
      return $ responseLBS status200 [] (encode users)

    "/api/download" -> do
      -- Path traversal vulnerability
      content <- downloadFile query
      return $ responseLBS status200 [] (BL.fromStrict content)

    "/api/execute" -> do
      -- Command injection vulnerability
      backupUserData query
      return $ responseLBS status200 [] "Backup completed"

    "/api/fetch" -> do
      -- SSRF vulnerability
      result <- fetchExternalAPI query
      return $ responseLBS status200 [] result

    "/api/redirect" -> do
      -- Open redirect vulnerability
      return $ redirectUser query

    _ -> return $ responseLBS status404 [] "Not found"

-- ============================================================================
-- COMPLEX BUSINESS LOGIC (Multiple Vulnerabilities Combined)
-- ============================================================================

-- User registration with multiple issues
registerNewUser :: String -> String -> String -> IO (Either String User)
registerNewUser username password email = do
  -- VULNERABILITY: No password strength check
  -- VULNERABILITY: Plain text password storage
  -- VULNERABILITY: Weak session token

  let token = generateSessionToken username  -- Weak
  gen <- getStdGen  -- VULNERABILITY: Global RNG
  let (randomId, _) = randomR (1, 999999) gen

  let newUser = User
        { userId = randomId
        , username = username
        , password = password  -- VULNERABILITY: Plain text
        , email = email
        , apiKey = secretKey  -- VULNERABILITY: Reusing secret
        , isAdmin = False
        , sessionToken = token
        , creditCard = Nothing
        }

  -- Save to database with SQL injection risk
  conn <- fmap fromJust $ readIORef globalDBConnection
  let sql = "INSERT INTO users (username, password) VALUES ('" ++ username ++ "', '" ++ password ++ "')"
  execute conn (Query $ C8.pack sql) ()  -- VULNERABILITY

  -- Add session with race condition
  addUserSession token newUser  -- VULNERABILITY

  return $ Right newUser

-- Complex data processing with multiple vulnerabilities
processUserData :: User -> String -> IO String
processUserData user inputData = do
  -- VULNERABILITY: fromJust
  let sessionData = fromJust $ lookup (sessionToken user) <$> readIORef globalSessions

  -- VULNERABILITY: Division by zero potential
  let dataSize = length inputData
  let chunkSize = if dataSize > 0 then dataSize `div` 0 else 0  -- VULN

  -- VULNERABILITY: Partial functions
  let firstChar = head inputData  -- VULN
  let lastChar = last inputData   -- VULN

  -- VULNERABILITY: Unsafe indexing
  let middleChar = inputData !! (length inputData `div` 2)  -- VULN

  -- VULNERABILITY: Race condition
  counter <- incrementAPICounter "/process"

  -- VULNERABILITY: Command injection
  system $ "echo 'Processing: " ++ inputData ++ "' >> /tmp/log.txt"

  return $ "Processed " ++ show counter ++ " times"

-- ============================================================================
-- MAIN APPLICATION
-- ============================================================================

-- Initialize vulnerable app
initVulnerableApp :: IO ()
initVulnerableApp = do
  putStrLn "Starting Vulnerable Web API..."
  putStrLn $ "Using secret key: " ++ secretKey  -- VULNERABILITY: Logging secrets
  putStrLn $ "Admin password: " ++ adminPassword  -- VULNERABILITY

  -- VULNERABILITY: Hard-coded connection string
  let connString = "host=localhost port=5432 user=admin password=" ++ databasePassword
  putStrLn $ "Connecting to: " ++ connString  -- VULNERABILITY: Logging credentials

-- Main entry point
main :: IO ()
main = do
  initVulnerableApp
  putStrLn "Vulnerable API running on port 8080"
  putStrLn "WARNING: This code contains intentional security vulnerabilities for testing!"
