{-# LANGUAGE PatternSynonyms #-}

-- SPDX-License-Identifier: LicenseRef-Proprietary
--
-- Copyright (c) 2026 Alexandre Boutrik. All Rights Reserved.
--
-- CONFIDENTIAL AND PROPRIETARY.
--
-- The intellectual and technical concepts contained herein are proprietary
-- to Alexandre Boutrik and are protected by trade secret, copyright and
-- patent law. Dissemination of this information or reproduction of this
-- material is strictly forbidden unless prior written permission is obtained.
--
-- Unauthorized access, use, reproduction, or distribution of this file is
-- strictly prohibited.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY EXPRESS
-- OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
-- NON-INFRINGEMENT ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
-- LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-- CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-- SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-- CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-- ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.

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

pattern CharK :: Word8
pattern CharK = 75

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

{- | Takes a raw payload from the C struct and drops unsupported/dangerous
ANSI escape sequences before packing it back into a strict ByteString.
We unpack the strict ByteString into a list here to leverage Haskell's
powerful list pattern matching for the ANSI state machine.
-}
sanitizePayload :: ByteString -> ByteString
sanitizePayload = BS.pack . stripAnsi . BS.unpack

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
string. It supports non-destructive leftward navigation, character
overwriting, and clearing lines, returning the updated buffer and the
new cursor position.
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

-- | Extracts the <n> multiplier from ANSI sequences (e.g. \ESC[3D -> 3)
parseAnsiParam :: [Word8] -> (Int, [Word8])
parseAnsiParam xs = parse 0 xs
  where
    parse acc (d : ds) | d >= CharZero && d <= CharNine = parse (acc * 10 + fromIntegral (d - CharZero)) ds
    parse acc ds = (max 1 acc, ds)

{- | A pure, recursive state machine that processes the incoming
 - byte stream.
It filters out dangerous or unprintable control characters, translates
specific supported ANSI escape codes (like Clear to End of Line) into
safe internal byte representations (e.g., byte 11), and completely
strips the remaining unsupported ANSI sequences to prevent
terminal corruption.
-}
stripAnsi :: [Word8] -> [Word8]
stripAnsi [] = []
-- Stop processing as soon as we hit the C-string null terminator.
stripAnsi (AsciiNull : _) = []
-- Detect OSC (Operating System Command) sequence
stripAnsi (AsciiEsc : AsciiBracketRight : xs) = stripAnsi (dropOscBody xs)
stripAnsi (AsciiEsc : AsciiBracketLeft : xs) =
    let (n, rest) = parseAnsiParam xs
     in case rest of
            (CharC : ys) -> replicate n InternalCursorRight ++ stripAnsi ys -- \ESC[<n>C (Right)
            (CharD : ys) -> replicate n InternalCursorLeft ++ stripAnsi ys -- \ESC[<n>D (Left)
            (CharP : ys) -> replicate n InternalDeleteChar ++ stripAnsi ys -- \ESC[<n>P (Delete)
            (CharAt : ys) -> replicate n InternalInsertSpace ++ stripAnsi ys -- \ESC[<n>@ (Insert)
            (CharK : ys) -> InternalClearEol : stripAnsi ys -- \ESC[<n>K (Clear EOL)
            _ -> stripAnsi (dropAnsiBody xs)
-- Catch isolated ESC bytes that might break rendering
stripAnsi (AsciiEsc : xs) = stripAnsi xs
-- Standard character processing
stripAnsi (x : xs)
    | isSafePrintable x = x : stripAnsi xs
    | otherwise = stripAnsi xs

{- | Consumes bytes inside an OSC (title) sequence until the terminator
 - is found.
-}
dropOscBody :: [Word8] -> [Word8]
dropOscBody [] = []
dropOscBody (AsciiBel : xs) = xs -- BEL terminator
dropOscBody (AsciiEsc : AsciiBackslash : xs) = xs -- ESC \ terminator
dropOscBody (_ : xs) = dropOscBody xs

{- | Consumes bytes inside an ANSI escape sequence until the terminator
is found. Standard ANSI sequences end with an ASCII byte in the range
64 to 126 ('@' to '~').
-}
dropAnsiBody :: [Word8] -> [Word8]
dropAnsiBody [] = []
dropAnsiBody (0 : _) = []
dropAnsiBody (x : xs)
    | x >= 64 && x <= 126 = xs -- Sequence terminator found, resume normal parsing
    | otherwise = dropAnsiBody xs -- Still inside sequence, keep dropping

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
