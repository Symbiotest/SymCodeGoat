{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE MultiWayIf #-}

module Core.DataProcessor where

import System.IO.Unsafe (unsafePerformIO)
import Foreign.Ptr (Ptr, peek, poke)
import Foreign.Storable (Storable)
import System.Random (mkStdGen, randomR)

-- | VULNERABILITY 1: unsafePerformIO in pure function
getCachedValue :: String -> Int
getCachedValue key = unsafePerformIO $ do
  putStrLn $ "Loading: " ++ key
  return 42

-- | SAFE: Protected division with guard
safeAverage :: [Int] -> Maybe Int
safeAverage xs
  | null xs = Nothing
  | otherwise = Just (sum xs `div` length xs)

-- | VULNERABILITY 2: Division by zero - no protection
calculateRatio :: Int -> Int -> Int
calculateRatio a b = a `div` b  -- UNSAFE!

-- | VULNERABILITY 3: Partial head without check
getFirstElement :: [a] -> a
getFirstElement xs = head xs  -- UNSAFE!

-- | SAFE: Protected head with pattern matching
safeFirst :: [a] -> Maybe a
safeFirst [] = Nothing
safeFirst (x:_) = Just x

-- | VULNERABILITY 4: Partial tail on potentially empty list
getAllButFirst :: [a] -> [a]
getAllButFirst xs = tail xs  -- UNSAFE!

-- | VULNERABILITY 5: Partial last
getLastElement :: [a] -> a
getLastElement xs = last xs  -- UNSAFE!

-- | VULNERABILITY 6: Partial !! operator
getElementAt :: [a] -> Int -> a
getElementAt xs i = xs !! i  -- UNSAFE!

-- | SAFE: Protected !! with bounds check
safeGetAt :: [a] -> Int -> Maybe a
safeGetAt xs i
  | i < 0 = Nothing
  | i >= length xs = Nothing
  | otherwise = Just (xs !! i)

-- | VULNERABILITY 7: mod without zero check
calculateMod :: Int -> Int -> Int
calculateMod x y = x `mod` y  -- UNSAFE!

-- | VULNERABILITY 8: quot without zero check
calculateQuot :: Int -> Int -> Int
calculateQuot x y = x `quot` y  -- UNSAFE!

-- | SAFE: Protected mod with guard
safeMod :: Int -> Int -> Maybe Int
safeMod x y
  | y == 0 = Nothing
  | otherwise = Just (x `mod` y)

-- | VULNERABILITY 9: rem without zero check
calculateRem :: Int -> Int -> Int
calculateRem x y = x `rem` y  -- UNSAFE!

-- | SAFE: Complex guards protecting division
complexDivision :: Int -> Int -> Int
complexDivision x y
  | y == 0 = 0
  | y < 0 = negate (x `div` abs y)
  | otherwise = x `div` y  -- SAFE: protected by guards

-- | VULNERABILITY 10: Unsafe pointer operations
unsafePeek :: Storable a => Ptr a -> a
unsafePeek ptr = unsafePerformIO (peek ptr)  -- UNSAFE!

-- | VULNERABILITY 11: Weak random number generator
weakRandom :: Int -> Int
weakRandom seed =
  let gen = mkStdGen seed  -- UNSAFE: weak PRNG
      (val, _) = randomR (1, 100) gen
  in val

-- | VULNERABILITY 12: error in guard (acceptable but flagged)
strictDivide :: Int -> Int -> Int
strictDivide x y
  | y == 0 = error "Division by zero"  -- Uses error
  | otherwise = x `div` y

-- | SAFE: Division protected by if-then-else
ifThenElseDivision :: Int -> Int -> Maybe Int
ifThenElseDivision x y =
  if y /= 0 then Just (x `div` y) else Nothing

-- | VULNERABILITY 13: Division in lambda without check
mapDivision :: [Int] -> Int -> [Int]
mapDivision xs divisor = map (\x -> x `div` divisor) xs  -- UNSAFE!

-- | SAFE: Division in lambda with check
safeMapDivision :: [Int] -> Int -> [Int]
safeMapDivision xs divisor =
  if divisor == 0
    then []
    else map (\x -> x `div` divisor) xs

-- | VULNERABILITY 14: Multiple unsafe operations in one function
processData :: [Int] -> Int -> Int -> Int
processData xs divisor index =
  let first = head xs  -- UNSAFE: head
      element = xs !! index  -- UNSAFE: !!
      ratio = first `div` divisor  -- UNSAFE: div
  in ratio + element

-- | SAFE: Multiple operations all protected
safeProcessData :: [Int] -> Int -> Int -> Maybe Int
safeProcessData xs divisor index
  | null xs = Nothing
  | index < 0 || index >= length xs = Nothing
  | divisor == 0 = Nothing
  | otherwise =
      let first = head xs  -- SAFE: protected by null check
          element = xs !! index  -- SAFE: protected by bounds check
          ratio = first `div` divisor  -- SAFE: protected by zero check
      in Just (ratio + element)

-- | SAFE: Pattern matching protects against empty list
foldOperation :: [Int] -> Int
foldOperation [] = 0
foldOperation xs = sum xs `div` length xs  -- SAFE: protected by pattern

-- | VULNERABILITY 15: Division by variable without protection in nested expression
complexCalculation :: Int -> Int -> Int -> Int
complexCalculation a b c =
  let intermediate = a * b
  in (intermediate + 100) `div` c  -- UNSAFE!

-- | SAFE: Literal divisor (should not be flagged)
divideByConstant :: Int -> Int
divideByConstant x = x `div` 10

-- | SAFE: Multi-clause pattern matching protecting division
patternDiv :: Int -> Int -> Int
patternDiv _ 0 = 0  -- Pattern matches zero
patternDiv x y = x `div` y  -- SAFE: protected by pattern above
