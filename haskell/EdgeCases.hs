{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiWayIf #-}

module Security.EdgeCases where

import System.IO.Unsafe (unsafePerformIO, unsafeDupablePerformIO, unsafeInterleaveIO)
import Foreign.Ptr
import Foreign.Storable
import System.Random (mkStdGen, getStdGen, setStdGen)
import Control.Exception (evaluate, assert)

-- | VULNERABILITY 1: All unsafePerformIO variants
unsafeRead :: String -> IO String
unsafeRead path = return $ unsafePerformIO (readFile path)  -- UNSAFE!

unsafeDupable :: Int -> Int
unsafeDupable x = unsafeDupablePerformIO (return x)  -- UNSAFE!

unsafeInterleave :: [Int] -> IO [Int]
unsafeInterleave xs = unsafeInterleaveIO (return xs)  -- UNSAFE!

-- | VULNERABILITY 2: All mkStdGen variants
weakRandom1 :: Int -> Int
weakRandom1 = fst . randomR (0, 100) . mkStdGen  -- UNSAFE!

weakRandom2 :: IO ()
weakRandom2 = setStdGen (mkStdGen 42)  -- UNSAFE!

weakRandom3 :: IO Int
weakRandom3 = do
  setStdGen (mkStdGen 12345)  -- UNSAFE!
  gen <- getStdGen
  return (fst $ randomR (0, 100) gen)

-- | VULNERABILITY 3: Pointer operations without bounds checking
unsafePeekOps :: Storable a => Ptr a -> a
unsafePeekOps = unsafePerformIO . peek  -- UNSAFE: both unsafePerformIO and peek!

unsafePokeOps :: Storable a => Ptr a -> a -> ()
unsafePokeOps ptr val = unsafePerformIO (poke ptr val)  -- UNSAFE!

-- | VULNERABILITY 4: error in various contexts
errorInPure :: Int -> Int
errorInPure 0 = error "zero not allowed"  -- UNSAFE!
errorInPure x = x * 2

errorInGuard :: Int -> Int -> String
errorInGuard x y
  | y == 0 = error "division by zero"  -- UNSAFE!
  | otherwise = show (x `div` y)

errorInCase :: Maybe Int -> Int
errorInCase mx = case mx of
  Nothing -> error "no value"  -- UNSAFE!
  Just x -> x

errorInLambda :: [Int] -> Int
errorInLambda xs = foldr (\x acc -> if x == 0 then error "zero found" else acc + x) 0 xs  -- UNSAFE!

-- | VULNERABILITY 5: undefined usage
undefinedInPattern :: Int -> Int
undefinedInPattern 0 = 1
undefinedInPattern _ = undefined  -- UNSAFE!

undefinedInBranch :: Bool -> Int
undefinedInBranch True = 42
undefinedInBranch False = undefined  -- UNSAFE!

-- | VULNERABILITY 6: assert usage (disabled in production but still bad practice)
assertInCode :: Int -> Int
assertInCode x = assert (x > 0) (x * 2)  -- UNSAFE!

-- | VULNERABILITY 7: Mixed unsafe operations in one function
mixedUnsafe1 :: [Int] -> Int -> IO Int
mixedUnsafe1 xs d = do
  let gen = mkStdGen 42  -- UNSAFE: weak PRNG
      first = head xs  -- UNSAFE: partial function
      ratio = first `div` d  -- UNSAFE: division
  return ratio

-- | VULNERABILITY 8: Chained unsafe operations
chainedUnsafe :: Storable a => Ptr a -> Int -> IO a
chainedUnsafe ptr offset = do
  let offsetPtr = unsafePerformIO (return ptr)  -- UNSAFE!
  peek (plusPtr offsetPtr offset)  -- UNSAFE!

-- | VULNERABILITY 9: Division in multi-way if
multiWayIfDiv :: Int -> Int -> Int
multiWayIfDiv x y = if
  | y > 100 -> x `div` 100
  | y > 50 -> x `div` 50
  | y > 0 -> x `div` y
  | otherwise -> x `div` (y + 1)  -- UNSAFE: y+1 could be 0 if y is -1

-- | VULNERABILITY 10: Division with where binding and guards
whereBindingDiv :: Int -> Int -> Int
whereBindingDiv x y
  | result > 100 = result
  | otherwise = result * 2
  where
    result = x `div` y  -- UNSAFE!

-- | VULNERABILITY 11: Unsafe operations in GADT
data SafetyLevel = Unsafe | Safe deriving (Show, Eq)

data Operation a where
  DivOp :: Int -> Int -> Operation Int  -- Division without check
  ModOp :: Int -> Int -> Operation Int  -- Mod without check
  SafeOp :: Int -> Int -> Operation Int -- Claims to be safe but isn't

executeOp :: Operation a -> a
executeOp (DivOp x y) = x `div` y  -- UNSAFE!
executeOp (ModOp x y) = x `mod` y  -- UNSAFE!
executeOp (SafeOp x y) = x `div` y  -- UNSAFE! (lie in the name)

-- | VULNERABILITY 12: Partial functions in type family context
type family GetFirst (xs :: [*]) :: * where
  GetFirst (x ': xs) = x
  GetFirst '[] = ()  -- Type level safety doesn't help runtime

getFirstValue :: [a] -> a
getFirstValue = head  -- UNSAFE!

-- | VULNERABILITY 13: Nested case expressions with division
nestedCaseDiv :: Maybe Int -> Maybe Int -> Int
nestedCaseDiv mx my = case mx of
  Nothing -> 0
  Just x -> case my of
    Nothing -> x
    Just y -> x `div` y  -- UNSAFE!

-- | VULNERABILITY 14: Division in record update
data Stats = Stats
  { total :: Int
  , count :: Int
  , average :: Int
  } deriving (Show)

calculateStats :: [Int] -> Stats
calculateStats xs = Stats
  { total = sum xs
  , count = length xs
  , average = sum xs `div` length xs  -- UNSAFE if xs is empty!
  }

-- | SAFE: Pattern protects record
calculateStatsSafe :: [Int] -> Stats
calculateStatsSafe [] = Stats 0 0 0
calculateStatsSafe xs = Stats
  { total = sum xs
  , count = length xs
  , average = sum xs `div` length xs  -- SAFE: pattern above
  }

-- | VULNERABILITY 15: Division in complex boolean expression
complexBoolDiv :: Int -> Int -> Int -> Bool
complexBoolDiv a b c =
  (a `div` b > 10) && (c `mod` b < 5)  -- UNSAFE: both operations!

-- | VULNERABILITY 16: Minimum/maximum on results
minMaxUnsafe :: [[Int]] -> (Int, Int)
minMaxUnsafe xss =
  let lengths = map length xss
  in (minimum lengths, maximum lengths)  -- UNSAFE if xss is empty!

-- | VULNERABILITY 17: head/tail on filtered results
filterAndHead :: [Int] -> Int
filterAndHead xs = head (filter (> 10) xs)  -- UNSAFE: filter might return empty!

filterAndTail :: [Int] -> [Int]
filterAndTail xs = tail (filter even xs)  -- UNSAFE!

filterAndLast :: [Int] -> Int
filterAndLast xs = last (filter odd xs)  -- UNSAFE!

-- | VULNERABILITY 18: !! on zipped lists
zipAndIndex :: [Int] -> [Int] -> Int -> Int
zipAndIndex xs ys i = zip xs ys !! i  -- UNSAFE!

-- | VULNERABILITY 19: Division in list operations
takeWhileDiv :: Int -> [Int] -> [Int]
takeWhileDiv d xs = takeWhile (\x -> (x `div` d) > 0) xs  -- UNSAFE!

dropWhileDiv :: Int -> [Int] -> [Int]
dropWhileDiv d xs = dropWhile (\x -> (x `div` d) < 10) xs  -- UNSAFE!

spanDiv :: Int -> [Int] -> ([Int], [Int])
spanDiv d xs = span (\x -> (x `div` d) > 5) xs  -- UNSAFE!

-- | VULNERABILITY 20: Unsafe operations in higher-order functions
applyUnsafe :: (Int -> Int -> Int) -> Int -> Int -> Int
applyUnsafe f x y = f x y

-- This function itself is not unsafe, but it can be used unsafely:
divApplied :: Int -> Int -> Int
divApplied = applyUnsafe div  -- The div here is UNSAFE when called!

-- | SAFE: Properly protected complex operation
safeComplexOperation :: [Int] -> Int -> Maybe Int
safeComplexOperation xs d
  | null xs = Nothing
  | d == 0 = Nothing
  | otherwise =
      let filtered = filter (> 0) xs
      in if null filtered
         then Nothing
         else Just (sum filtered `div` d)
