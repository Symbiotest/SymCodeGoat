{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- Complex Web Application with Cryptographic Operations
-- This code intentionally contains sophisticated security vulnerabilities
-- for testing Opengrep detection capabilities

module ComplexWebApp where

import Control.Concurrent (forkIO, threadDelay, MVar, newMVar, takeMVar, putMVar)
import Control.Exception (catch, SomeException, evaluate)
import Control.Monad (forM_, when, unless)
import Data.Bits (xor, shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Data.List (foldl', sort, head, tail, last, init)
import Data.Maybe (fromJust, fromMaybe, isNothing)
import Data.Time.Clock (getCurrentTime, UTCTime)
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr, nullPtr, castPtr)
import Foreign.Storable (peek, poke, sizeOf)
import Foreign.Marshal.Alloc (malloc, free)
import GHC.Generics (Generic)
import System.IO.Unsafe (unsafePerformIO, unsafeInterleaveIO)
import System.Process (system, readProcess, callCommand)
import System.Random (mkStdGen, randomR, getStdGen, randomRIO)
import Text.Read (readMaybe)

-- ============================================================================
-- VULNERABILITY 1: Global Mutable State with Race Conditions
-- ============================================================================

-- Global session cache (UNSAFE: race conditions + breaks referential transparency)
{-# NOINLINE globalSessionCache #-}
globalSessionCache :: IORef [(String, Session)]
globalSessionCache = unsafePerformIO (newIORef [])

-- Global request counter (UNSAFE: non-atomic operations)
{-# NOINLINE requestCounter #-}
requestCounter :: IORef Int
requestCounter = unsafePerformIO (newIORef 0)

-- Global API key storage (UNSAFE: mutable global state)
{-# NOINLINE apiKeys #-}
apiKeys :: IORef [String]
apiKeys = unsafePerformIO (newIORef [])

-- ============================================================================
-- VULNERABILITY 2: Weak Custom Cryptography
-- ============================================================================

-- Custom XOR "encryption" (VULNERABILITY: weak crypto)
encryptData :: String -> Word8 -> String
encryptData plaintext key = map (\c -> toEnum $ fromEnum c `xor` fromEnum key) plaintext

-- Simple substitution cipher (VULNERABILITY: broken crypto)
caesarCipher :: Int -> String -> String
caesarCipher shift text = map shiftChar text
  where
    shiftChar c
      | c >= 'a' && c <= 'z' = toEnum $ (fromEnum c - fromEnum 'a' + shift) `mod` 26 + fromEnum 'a'
      | c >= 'A' && c <= 'Z' = toEnum $ (fromEnum c - fromEnum 'A' + shift) `mod` 26 + fromEnum 'A'
      | otherwise = c

-- Custom hash function (VULNERABILITY: weak hash)
customHash :: String -> Int
customHash = foldl' (\acc c -> (acc * 31 + fromEnum c) `mod` 1000000) 0

-- ============================================================================
-- VULNERABILITY 3: Unsafe Random Number Generation
-- ============================================================================

-- Predictable session token generation (VULNERABILITY: weak RNG)
generateSessionToken :: String -> String
generateSessionToken username =
  let seed = customHash username
      gen = mkStdGen seed  -- VULNERABILITY: predictable seed
      (random1, gen2) = randomR (1000, 9999) gen
      (random2, _) = randomR (1000, 9999) gen2
  in username ++ "-" ++ show random1 ++ "-" ++ show random2

-- Weak password generation (VULNERABILITY: getStdGen global state)
generateWeakPassword :: IO String
generateWeakPassword = do
  gen <- getStdGen  -- VULNERABILITY: global RNG state
  let (r1, gen2) = randomR (100000, 999999) gen
  return $ "pass" ++ show r1

-- ============================================================================
-- VULNERABILITY 4: Unsafe Pointer Operations
-- ============================================================================

-- Data structure for in-memory cache
data CacheEntry = CacheEntry
  { cacheKey :: String
  , cacheValue :: ByteString
  , cacheTimestamp :: UTCTime
  } deriving (Show, Generic)

-- Unsafe memory manipulation (VULNERABILITY: no null checks, unsafe casts)
storeInMemoryCache :: String -> Int -> IO ()
storeInMemoryCache key value = do
  ptr <- malloc :: IO (Ptr Int)
  poke ptr value  -- VULNERABILITY: no error handling

  -- Unsafe cast without validation
  let bytePtr = castPtr ptr :: Ptr Word8
  byte <- peek bytePtr  -- VULNERABILITY: type confusion

  putStrLn $ "Stored " ++ show byte ++ " bytes for key: " ++ key
  free ptr

-- Reading from potentially null pointer (VULNERABILITY)
readFromCache :: Ptr Int -> IO Int
readFromCache ptr = do
  -- VULNERABILITY: no null pointer check
  value <- peek ptr
  return value

-- Unsafe pointer arithmetic
unsafePtrOperation :: Ptr Word32 -> Int -> IO Word32
unsafePtrOperation basePtr offset = do
  -- VULNERABILITY: no bounds checking
  let targetPtr = basePtr `plusPtr` (offset * sizeOf (undefined :: Word32))
  peek targetPtr

-- ============================================================================
-- VULNERABILITY 5: Partial Functions and Unsafe List Operations
-- ============================================================================

-- User session management
data Session = Session
  { sessionId :: String
  , userId :: String
  , loginTime :: UTCTime
  } deriving (Show)

-- Get first active session (VULNERABILITY: partial function)
getFirstSession :: [Session] -> Session
getFirstSession sessions = head sessions  -- VULNERABILITY: crashes on empty list

-- Get most recent session (VULNERABILITY: partial functions)
getMostRecentSession :: [Session] -> Session
getMostRecentSession sessions = last sessions  -- VULNERABILITY: crashes on empty

-- Remove oldest session (VULNERABILITY: partial functions)
removeOldestSession :: [Session] -> [Session]
removeOldestSession sessions = tail sessions  -- VULNERABILITY: crashes on empty

-- Get all but last session (VULNERABILITY: partial functions)
getAllButLastSession :: [Session] -> [Session]
getAllButLastSession sessions = init sessions  -- VULNERABILITY: crashes on empty

-- Access session by index (VULNERABILITY: unsafe indexing)
getSessionAt :: [Session] -> Int -> Session
getSessionAt sessions idx = sessions !! idx  -- VULNERABILITY: no bounds check

-- ============================================================================
-- VULNERABILITY 6: Division by Zero and Arithmetic Errors
-- ============================================================================

-- Calculate average response time (VULNERABILITY: division by zero)
calculateAverageResponseTime :: [Int] -> Double
calculateAverageResponseTime times =
  let total = sum times
      count = length times
  in fromIntegral total / fromIntegral count  -- VULNERABILITY: count could be 0

-- Rate limiting calculation (VULNERABILITY: mod by zero)
checkRateLimit :: Int -> Int -> Bool
checkRateLimit requests window =
  let rate = requests `mod` window  -- VULNERABILITY: window could be 0
  in rate < 100

-- Quota calculation (VULNERABILITY: quot by zero)
calculateQuota :: Int -> Int -> Int
calculateQuota total users = total `quot` users  -- VULNERABILITY: users could be 0

-- Remainder calculation (VULNERABILITY: rem with zero)
calculateRemainder :: Int -> Int -> Int
calculateRemainder value divisor = value `rem` divisor  -- VULNERABILITY

-- ============================================================================
-- VULNERABILITY 7: Command Injection via System Calls
-- ============================================================================

-- Execute system backup (VULNERABILITY: command injection)
backupDatabase :: String -> IO ()
backupDatabase dbName = do
  let cmd = "pg_dump " ++ dbName ++ " > backup.sql"
  system cmd  -- VULNERABILITY: unsanitized input
  return ()

-- Process uploaded file (VULNERABILITY: command injection)
processUploadedFile :: String -> IO String
processUploadedFile filename = do
  -- VULNERABILITY: shell command with user input
  output <- readProcess "file" ["-b", filename] ""
  return output

-- Clean temporary files (VULNERABILITY: command injection)
cleanupTempFiles :: String -> IO ()
cleanupTempFiles pattern = do
  callCommand $ "rm -rf /tmp/" ++ pattern  -- VULNERABILITY: injection

-- ============================================================================
-- VULNERABILITY 8: Race Conditions and Concurrency Issues
-- ============================================================================

-- Increment request counter (VULNERABILITY: race condition)
incrementRequestCount :: IO Int
incrementRequestCount = do
  count <- readIORef requestCounter
  threadDelay 10  -- Simulate processing
  let newCount = count + 1
  writeIORef requestCounter newCount  -- VULNERABILITY: non-atomic read-modify-write
  return newCount

-- Process concurrent requests (VULNERABILITY: unhandled exceptions in threads)
processConcurrentRequests :: [String] -> IO ()
processConcurrentRequests requests = do
  forM_ requests $ \req -> do
    forkIO $ do  -- VULNERABILITY: exceptions not caught
      count <- incrementRequestCount
      processRequest req count

-- Handle session with MVar (VULNERABILITY: potential deadlock)
processWithLock :: MVar Session -> IO ()
processWithLock sessionVar = do
  session <- takeMVar sessionVar  -- VULNERABILITY: if exception occurs here
  -- Process session
  threadDelay 1000000
  -- VULNERABILITY: putMVar might not be called if exception occurs
  putMVar sessionVar session

-- ============================================================================
-- VULNERABILITY 9: Unsafe Error Handling
-- ============================================================================

-- Parse user input (VULNERABILITY: error instead of Maybe)
parseUserId :: String -> Int
parseUserId str = case readMaybe str of
  Just n -> n
  Nothing -> error $ "Invalid user ID: " ++ str  -- VULNERABILITY: throws error

-- Get required config (VULNERABILITY: undefined on failure)
getRequiredConfig :: String -> String
getRequiredConfig key =
  unsafePerformIO $ do
    -- Simulate config lookup
    return undefined  -- VULNERABILITY: undefined value

-- Extract value from Maybe (VULNERABILITY: fromJust)
extractSessionId :: Maybe String -> String
extractSessionId = fromJust  -- VULNERABILITY: crashes on Nothing

-- ============================================================================
-- VULNERABILITY 10: Timing-Based Information Leakage
-- ============================================================================

-- Password verification with timing leak (VULNERABILITY)
verifyPasswordUnsafe :: String -> String -> Bool
verifyPasswordUnsafe stored input = stored == input  -- VULNERABILITY: timing attack

-- Custom comparison with early exit (VULNERABILITY: timing leak)
constantTimeCompare :: String -> String -> Bool
constantTimeCompare s1 s2
  | length s1 /= length s2 = False
  | otherwise = and $ zipWith (==) s1 s2  -- VULNERABILITY: early exit on mismatch

-- ============================================================================
-- VULNERABILITY 11: Unsafe Lazy IO
-- ============================================================================

-- Read log file lazily (VULNERABILITY: resource leak)
readLogsLazily :: FilePath -> IO String
readLogsLazily path = unsafeInterleaveIO $ do
  contents <- readFile path  -- VULNERABILITY: lazy IO with unsafeInterleaveIO
  return contents

-- ============================================================================
-- MAIN APPLICATION LOGIC
-- ============================================================================

data User = User
  { username :: String
  , passwordHash :: Int
  , apiKey :: String
  } deriving (Show)

-- Process request with multiple vulnerabilities
processRequest :: String -> Int -> IO ()
processRequest requestData requestId = do
  putStrLn $ "Processing request #" ++ show requestId

  -- VULNERABILITY: Parse without validation
  let userId = parseUserId (take 5 requestData)

  -- VULNERABILITY: Weak crypto
  let encrypted = encryptData requestData 42

  -- VULNERABILITY: Race condition
  sessions <- readIORef globalSessionCache

  -- VULNERABILITY: Partial function
  unless (null sessions) $ do
    let firstSession = getFirstSession sessions
    putStrLn $ "Active session: " ++ sessionId firstSession

  -- VULNERABILITY: Division by zero potential
  let avgTime = calculateAverageResponseTime [100, 200, 300]
  putStrLn $ "Average time: " ++ show avgTime

-- Authenticate user with multiple vulnerabilities
authenticateUser :: String -> String -> IO Bool
authenticateUser username password = do
  -- VULNERABILITY: Weak hash
  let passHash = customHash password

  -- VULNERABILITY: Timing attack
  let stored = "admin"
  let result = verifyPasswordUnsafe stored username

  -- VULNERABILITY: Weak random token
  let token = generateSessionToken username

  -- VULNERABILITY: Global state mutation
  sessions <- readIORef globalSessionCache
  currentTime <- getCurrentTime
  let newSession = Session token username currentTime
  writeIORef globalSessionCache ((token, newSession) : sessions)

  return result

-- Initialize application with vulnerabilities
initApplication :: IO ()
initApplication = do
  putStrLn "Initializing Complex Web Application..."

  -- VULNERABILITY: Weak password generation
  defaultPass <- generateWeakPassword
  putStrLn $ "Generated default password: " ++ defaultPass

  -- VULNERABILITY: Command injection
  backupDatabase "production_db"

  -- VULNERABILITY: Unsafe pointer operations
  storeInMemoryCache "config" 42

  putStrLn "Application initialized with multiple security vulnerabilities!"

-- Complex calculation with vulnerabilities
performComplexCalculation :: [Int] -> [Int] -> Int
performComplexCalculation list1 list2 =
  let sum1 = sum list1
      sum2 = sum list2
      -- VULNERABILITY: Division by zero
      ratio = sum1 `div` sum2
      -- VULNERABILITY: Partial functions
      first1 = head list1
      last2 = last list2
      -- VULNERABILITY: Unsafe indexing
      middle1 = list1 !! (length list1 `div` 2)
  in ratio + first1 + last2 + middle1

main :: IO ()
main = do
  initApplication

  -- Simulate concurrent request processing
  processConcurrentRequests ["req1", "req2", "req3"]

  -- Authenticate user
  authenticated <- authenticateUser "admin" "password123"
  putStrLn $ "Authenticated: " ++ show authenticated

  -- Perform calculation
  let result = performComplexCalculation [1, 2, 3, 4, 5] [10, 20, 30]
  putStrLn $ "Calculation result: " ++ show result

  putStrLn "Complex web application running with security vulnerabilities!"
