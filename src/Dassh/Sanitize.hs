{-# LANGUAGE PatternSynonyms #-}

-- SPDX-License-Identifier: EUPL-1.2
--
-- Copyright 2026 Alexandre Boutrik
--
-- Licensed under the EUPL, Version 1.2 or - as soon they will be approved by
-- the European Commission - subsequent versions of the EUPL (the "Licence");
-- You may not use this work except in compliance with the Licence.
-- You may obtain a copy of the Licence at:
--
-- https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the Licence is distributed on an "AS IS" basis,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the Licence for the specific language governing permissions and
-- limitations under the Licence.

{- |
Module      : Dassh.Sanitize
Description : Pure functional sanitization engine for raw eBPF payloads.

This module provides the security boundary for dassh. It receives raw
byte streams (Word8 arrays) from the eBPF ring buffer and sanitizes them
by stripping common ANSI escape sequences (colors, cursor movements) and
filtering out non-printable control characters. It should prevent terminal
corruption and mitigate Remote Code Execution (RCE) vectors via crafted
escape sequences.
-}
module Dassh.Sanitize (
    sanitizePayload,
    applyTerminalState,
    isCompletionGarbage,
) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Data.Word (Word8)

-- | Standard ASCII Control Characters
pattern AsciiNull :: Word8
pattern AsciiNull = 0

pattern AsciiBel :: Word8
pattern AsciiBel = 7

pattern AsciiBs :: Word8
pattern AsciiBs = 8

pattern AsciiTab :: Word8
pattern AsciiTab = 9

pattern AsciiLf :: Word8
pattern AsciiLf = 10

pattern AsciiCr :: Word8
pattern AsciiCr = 13

pattern AsciiEsc :: Word8
pattern AsciiEsc = 27

pattern AsciiSpace :: Word8
pattern AsciiSpace = 32

-- | ASCII characters used in ANSI escape parsing
pattern CharZero :: Word8
pattern CharZero = 48

pattern CharNine :: Word8
pattern CharNine = 57

pattern CharAt :: Word8
pattern CharAt = 64

pattern CharC :: Word8
pattern CharC = 67

pattern CharD :: Word8
pattern CharD = 68

pattern CharH :: Word8
pattern CharH = 104

pattern CharK :: Word8
pattern CharK = 75

pattern CharL :: Word8
pattern CharL = 108

pattern CharP :: Word8
pattern CharP = 80

pattern AsciiBracketLeft :: Word8
pattern AsciiBracketLeft = 91

pattern AsciiBackslash :: Word8
pattern AsciiBackslash = 92

pattern AsciiBracketRight :: Word8
pattern AsciiBracketRight = 93

pattern AsciiTilde :: Word8
pattern AsciiTilde = 126

-- | Internal markers for 1D terminal emulation
pattern InternalClearEol :: Word8
pattern InternalClearEol = 11

pattern InternalDeleteChar :: Word8
pattern InternalDeleteChar = 12

pattern InternalCursorRight :: Word8
pattern InternalCursorRight = 14

pattern InternalCursorLeft :: Word8
pattern InternalCursorLeft = 15

pattern InternalInsertSpace :: Word8
pattern InternalInsertSpace = 16

-- | UTF-8 boundaries for continuation bytes
pattern Utf8ContStart :: Word8
pattern Utf8ContStart = 128

pattern Utf8ContEnd :: Word8
pattern Utf8ContEnd = 191

-- | Additional ASCII characters for TUI detection
pattern CharQuestionMark :: Word8
pattern CharQuestionMark = 63

pattern CharSemicolon :: Word8
pattern CharSemicolon = 59

pattern CharUnderscore :: Word8
pattern CharUnderscore = 95

pattern CharCaret :: Word8
pattern CharCaret = 94

{- |
Core sanitization pipeline. Transforms a raw C-struct byte stream into
a safe, UI-ready ByteString while dropping dangerous ANSI sequences.

Because the kernel eBPF ring buffer chunks data into fixed 256-byte blocks,
long ANSI sequences (like DCS capability queries) may be arbitrarily severed.
This function relies on a chunk-agnostic, "starvable" state machine. It
threads a staging buffer recursively, pausing execution and holding
incomplete sequences in memory until the kernel delivers the
remaining fragments.

Returns: (IsTuiModeActive, LeftoverAnsiFragments, SafeRenderableData).
-}
sanitizePayload :: Bool -> ByteString -> ByteString -> (Bool, ByteString, ByteString)
sanitizePayload tuiMode staging bs =
    let cleanBs = fst (BS.break (== AsciiNull) bs)
        combined = BS.append staging cleanBs
        -- Protect against infinite growth if sequence terminator is missing
        boundedCombined = if BS.length combined > 4096 then BS.drop (BS.length combined - 4096) combined else combined
        (finalTui, safeChars, leftover) = stripAnsi tuiMode (BS.unpack boundedCombined)
     in (finalTui, BS.pack leftover, BS.pack safeChars)

{- | Heuristic filter to identify and drop internal Bash tab-completion
 - pipe garbage.
This allows us to safely monitor stdout (fd 1) for built-ins like `pwd`
without polluting the UI with internal autocomplete script configurations.
-}
isCompletionGarbage :: ByteString -> Bool
isCompletionGarbage bs =
    BS.isInfixOf (BC.pack "complete ") bs
        || BS.isInfixOf (BC.pack "compgen ") bs
        || BS.isInfixOf (BC.pack "_comp_") bs

{- | Applies terminal control characters (\r, \b, \ESC[K) to the
 - existing buffer.
Instead of a complex 2D array, this function simulates terminal behavior
on a 1D ByteString by maintaining a 'cursor offset' from the end of the
string.
-}
applyTerminalState :: ByteString -> Int -> ByteString -> (ByteString, Int)
applyTerminalState oldBuf oldOffset newBytes = go oldBuf oldOffset (BS.unpack newBytes)
  where
    go b off [] = (b, off)
    go b off (AsciiBs : xs) = cursorLeft b off xs -- \b (Cursor Left)
    go b off (InternalCursorLeft : xs) = cursorLeft b off xs -- \ESC[D (Cursor Left)
    go b off (InternalCursorRight : xs) = cursorRight b off xs -- \ESC[C (Cursor Right)
    go b off (InternalDeleteChar : xs) -- \ESC[<n>P (Delete Character)
        | off == 0 = go b off xs
        | otherwise =
            let (pre, post) = BS.splitAt (BS.length b - off) b
                newB = pre `BS.append` dropFullChar post
             in go newB (max 0 (off - 1)) xs
    go b off (InternalInsertSpace : xs) -- \ESC[<n>@ (Insert blank space)
        =
        let (pre, post) = BS.splitAt (BS.length b - off) b
            newB = BS.snoc pre AsciiSpace `BS.append` post
         in go newB (off + 1) xs
    go b off (AsciiTab : xs) -- \t (Tab Expansion)
        =
        let (pre, post) = BS.splitAt (BS.length b - off) b
            lineLen = BS.length (snd $ BS.breakEnd (== AsciiLf) pre)
            spacesNeeded = 8 - (lineLen `mod` 8)
            spaces = BS.replicate spacesNeeded AsciiSpace
         in go (pre `BS.append` spaces `BS.append` post) off xs
    go b _ (AsciiCr : AsciiLf : xs) -- \r\n
        =
        go (BS.snoc b AsciiLf) 0 xs
    go b _ (AsciiCr : xs) -- \r (Isolated Carriage Return)
        =
        let currentLineLen = BS.length (snd $ BS.breakEnd (== AsciiLf) b)
         in go b currentLineLen xs
    go b off (InternalClearEol : xs) -- \ESC[K (Clear to end of line)
        | off == 0 = go b off xs
        | otherwise = go (BS.take (BS.length b - off) b) 0 xs
    go b off (x : xs)
        | off == 0 = go (BS.snoc b x) 0 xs
        | x >= Utf8ContStart && x <= Utf8ContEnd -- UTF-8 continuation byte: always insert, never drop
            =
            let (pre, post) = BS.splitAt (BS.length b - off) b
                newB = BS.snoc pre x `BS.append` post
             in go newB off xs
        | otherwise -- Overwrite characters if cursor is shifted left
            =
            let (pre, post) = BS.splitAt (BS.length b - off) b
                newB = BS.snoc pre x `BS.append` dropFullChar post
             in go newB (max 0 (off - 1)) xs

    -- Helper to drop exactly one full character (accounting for UTF-8)
    dropFullChar p =
        if BS.length p > 0
            then
                let p' = BS.drop 1 p
                    skipCont p'' =
                        if BS.length p'' > 0 && BS.head p'' >= Utf8ContStart && BS.head p'' <= Utf8ContEnd
                            then skipCont (BS.drop 1 p'')
                            else p''
                 in skipCont p'
            else p

    -- Helper to safely move left without slicing UTF-8
    cursorLeft b off xs
        | BS.null b = go b off xs
        | off < BS.length b && BS.index b (BS.length b - 1 - off) == AsciiLf = go b off xs
        | otherwise =
            let skipCont o =
                    if o < BS.length b && BS.index b (BS.length b - 1 - o) >= Utf8ContStart && BS.index b (BS.length b - 1 - o) <= Utf8ContEnd
                        then skipCont (o + 1)
                        else o
             in go b (skipCont (off + 1)) xs

    -- Helper to safely move right without slicing UTF-8
    cursorRight b off xs
        | off == 0 = go b off xs
        | otherwise =
            let skipCont o =
                    if o > 0 && BS.index b (BS.length b - o) >= Utf8ContStart && BS.index b (BS.length b - o) <= Utf8ContEnd
                        then skipCont (o - 1)
                        else o
             in go b (skipCont (off - 1)) xs

{- | Extracts all semicolon-separated numeric parameters from the CSI body.
Ignores non-numeric characters to prevent formatting failures.
-}
parseCsiParams :: [Word8] -> [Int]
parseCsiParams = go [] 0 False
  where
    go acc cur has [] = reverse (if has then cur : acc else acc)
    go acc cur has (d : ds)
        | d >= CharZero && d <= CharNine = go acc (cur * 10 + fromIntegral (d - CharZero)) True ds
        | d == CharSemicolon = go (if has then cur : acc else acc) 0 False ds
        | otherwise = go acc cur has ds -- Ignore any other invalid
        -- characters like spaces

{- |
A pure, recursive 1D state machine.
It isolates safe control characters for terminal emulation while stripping
unsupported ANSI escape codes to prevent Brick UI corruption.

If 'tuiMode' is true, it operates in a strict O(1) drop-mode, discarding
standard characters at the parser root to prevent Alternative Screen UI
elements from leaking into the dashboard's scrollback buffers.
-}
stripAnsi :: Bool -> [Word8] -> (Bool, [Word8], [Word8])
stripAnsi tui [] = (tui, [], [])
-- Detect Terminal Strings: OSC (]), DCS (P), APC (_), PM (^) and drop them
stripAnsi tui (AsciiEsc : AsciiBracketRight : xs) = dropStringBody tui xs
stripAnsi tui (AsciiEsc : CharP : xs) = dropStringBody tui xs
stripAnsi tui (AsciiEsc : CharUnderscore : xs) = dropStringBody tui xs
stripAnsi tui (AsciiEsc : CharCaret : xs) = dropStringBody tui xs
-- Detect CSI (Control Sequence Introducer)
stripAnsi tui orig@(AsciiEsc : AsciiBracketLeft : xs) = parseCsi tui orig xs
-- Detect standard ESC sequences (Catch-all for \ESC > or \ESC ( B)
stripAnsi tui orig@(AsciiEsc : xs) = parseEsc tui orig xs
-- Standard character processing
stripAnsi tui (x : xs)
    | isSafePrintable x =
        let (fTui, safe, left) = stripAnsi tui xs
         in -- Discard printable characters instantly if a TUI is active
            (fTui, if tui then safe else x : safe, left)
    | otherwise = stripAnsi tui xs

{- | Consumes bytes inside a string sequence (OSC, DCS, etc.) until
 - the terminator is found. Uses dummy headers to cap memory at O(1).
-}
dropStringBody :: Bool -> [Word8] -> (Bool, [Word8], [Word8])
dropStringBody tui [] = (tui, [], [AsciiEsc, CharP])
dropStringBody tui (AsciiBel : xs) = stripAnsi tui xs
dropStringBody tui (AsciiEsc : AsciiBackslash : xs) = stripAnsi tui xs
dropStringBody tui [AsciiEsc] = (tui, [], [AsciiEsc, CharP, AsciiEsc]) -- Starved on ESC
dropStringBody tui (_ : xs) = dropStringBody tui xs

{- | Parses CSI sequences and translates supported commands.
Returns leftovers if the sequence is incomplete.
-}
parseCsi :: Bool -> [Word8] -> [Word8] -> (Bool, [Word8], [Word8])
parseCsi tui original xs =
    let (body, rest) = break (\x -> x >= CharAt && x <= AsciiTilde) xs
     in case rest of
            [] -> (tui, [], original) -- Starved
            (term : fullRest) ->
                let (isPrivate, pBody) = case body of
                        (CharQuestionMark : ys) -> (True, ys)
                        _ -> (False, body)
                    params = parseCsiParams pBody
                    n = case params of [] -> 1; (p : _) -> max 1 p
                    isTuiMode p = p `elem` [47, 1047, 1049]
                 in case term of
                        CharH | any isTuiMode params -> stripAnsi True fullRest
                        CharL | any isTuiMode params -> stripAnsi False fullRest
                        CharC
                            | not isPrivate ->
                                let (fTui, safe, left) = stripAnsi tui fullRest
                                 in (fTui, if tui then safe else replicate n InternalCursorRight ++ safe, left)
                        CharD
                            | not isPrivate ->
                                let (fTui, safe, left) = stripAnsi tui fullRest
                                 in (fTui, if tui then safe else replicate n InternalCursorLeft ++ safe, left)
                        CharP
                            | not isPrivate ->
                                let (fTui, safe, left) = stripAnsi tui fullRest
                                 in (fTui, if tui then safe else replicate n InternalDeleteChar ++ safe, left)
                        CharAt
                            | not isPrivate ->
                                let (fTui, safe, left) = stripAnsi tui fullRest
                                 in (fTui, if tui then safe else replicate n InternalInsertSpace ++ safe, left)
                        CharK
                            | not isPrivate ->
                                let (fTui, safe, left) = stripAnsi tui fullRest
                                 in (fTui, if tui then safe else InternalClearEol : safe, left)
                        _ -> stripAnsi tui fullRest

{- | Parses and drops standard ESC sequences (like character set selections).
Returns leftovers if the sequence is incomplete.
-}
parseEsc :: Bool -> [Word8] -> [Word8] -> (Bool, [Word8], [Word8])
parseEsc tui original [] = (tui, [], original)
parseEsc tui original (x : xs)
    | x >= 48 && x <= 126 = stripAnsi tui xs -- Sequence complete, drop it.
    | x >= 32 && x <= 47 = parseEsc tui (original ++ [x]) xs -- Intermediate byte
    | otherwise = stripAnsi tui xs -- Invalid, abort dropping

{- | Determines if a byte is safe to pass to the Brick UI state machine.
Allows standard ASCII printables, UTF-8 extended bytes, and specific
control characters mapped for our 1D cursor emulation.
-}
isSafePrintable :: Word8 -> Bool
isSafePrintable x =
    (x >= AsciiSpace && x <= AsciiTilde)
        || x >= Utf8ContStart
        || x
            `elem` [ AsciiBs
                   , AsciiTab
                   , AsciiLf
                   , InternalClearEol
                   , InternalDeleteChar
                   , AsciiCr
                   , InternalCursorRight
                   , InternalCursorLeft
                   , InternalInsertSpace
                   ]
