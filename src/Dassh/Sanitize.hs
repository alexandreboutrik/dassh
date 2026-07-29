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
    go b off (8 : xs) = cursorLeft b off xs -- \b (Cursor Left)
    go b off (15 : xs) = cursorLeft b off xs -- \ESC[D (Cursor Left)
    go b off (14 : xs) = cursorRight b off xs -- \ESC[C (Cursor Right)
    go b off (12 : xs) -- \ESC[<n>P (Delete Character)
        | off == 0 = go b off xs
        | otherwise =
            let (pre, post) = BS.splitAt (BS.length b - off) b
                newB = pre `BS.append` dropFullChar post
             in go newB (max 0 (off - 1)) xs
    go b off (16 : xs) -- \ESC[<n>@ (Insert blank space)
        =
        let (pre, post) = BS.splitAt (BS.length b - off) b
            newB = BS.snoc pre 32 `BS.append` post
         in go newB (off + 1) xs
    go b off (9 : xs) -- \t (Tab Expansion)
        =
        let (pre, post) = BS.splitAt (BS.length b - off) b
            lineLen = BS.length (snd $ BS.breakEnd (== 10) pre)
            spacesNeeded = 8 - (lineLen `mod` 8)
            spaces = BS.replicate spacesNeeded 32
         in go (pre `BS.append` spaces `BS.append` post) off xs
    go b _ (13 : 10 : xs) -- \r\n
        =
        go (BS.snoc b 10) 0 xs
    go b _ (13 : xs) -- \r (Isolated Carriage Return)
        =
        let currentLineLen = BS.length (snd $ BS.breakEnd (== 10) b)
         in go b currentLineLen xs
    go b off (11 : xs) -- \ESC[K (Clear to end of line)
        | off == 0 = go b off xs
        | otherwise = go (BS.take (BS.length b - off) b) 0 xs
    go b off (x : xs)
        | off == 0 = go (BS.snoc b x) 0 xs
        | x >= 128 && x <= 191 -- UTF-8 continuation byte: always insert, never drop
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
                        if BS.length p'' > 0 && BS.head p'' >= 128 && BS.head p'' <= 191
                            then skipCont (BS.drop 1 p'')
                            else p''
                 in skipCont p'
            else p

    -- Helper to safely move left without slicing UTF-8
    cursorLeft b off xs
        | BS.null b = go b off xs
        | off < BS.length b && BS.index b (BS.length b - 1 - off) == 10 = go b off xs
        | otherwise =
            let skipCont o =
                    if o < BS.length b && BS.index b (BS.length b - 1 - o) >= 128 && BS.index b (BS.length b - 1 - o) <= 191
                        then skipCont (o + 1)
                        else o
             in go b (skipCont (off + 1)) xs

    -- Helper to safely move right without slicing UTF-8
    cursorRight b off xs
        | off == 0 = go b off xs
        | otherwise =
            let skipCont o =
                    if o > 0 && BS.index b (BS.length b - o) >= 128 && BS.index b (BS.length b - o) <= 191
                        then skipCont (o - 1)
                        else o
             in go b (skipCont (off - 1)) xs

-- | Extracts the <n> multiplier from ANSI sequences (e.g. \ESC[3D -> 3)
parseAnsiParam :: [Word8] -> (Int, [Word8])
parseAnsiParam xs = parse 0 xs
  where
    parse acc (d : ds) | d >= 48 && d <= 57 = parse (acc * 10 + fromIntegral (d - 48)) ds
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
-- The eBPF struct payload is 256 bytes, mostly padded with 0s at the end.
stripAnsi (0 : _) = []
-- Detect OSC (Operating System Command) sequence: ESC (27) followed by ']' (93)
stripAnsi (27 : 93 : xs) = stripAnsi (dropOscBody xs)
stripAnsi (27 : 91 : xs) =
    let (n, rest) = parseAnsiParam xs
     in case rest of
            (67 : ys) -> replicate n 14 ++ stripAnsi ys -- \ESC[<n>C (Right)
            (68 : ys) -> replicate n 15 ++ stripAnsi ys -- \ESC[<n>D (Left)
            (80 : ys) -> replicate n 12 ++ stripAnsi ys -- \ESC[<n>P (Delete)
            (64 : ys) -> replicate n 16 ++ stripAnsi ys -- \ESC[<n>@ (Insert)
            (75 : ys) -> 11 : stripAnsi ys -- \ESC[<n>K (Clear EOL)
            _ -> stripAnsi (dropAnsiBody xs)
-- Catch isolated ESC bytes that might break rendering
stripAnsi (27 : xs) = stripAnsi xs
-- Standard character processing
stripAnsi (x : xs)
    | isSafePrintable x = x : stripAnsi xs
    | otherwise = stripAnsi xs

{- | Consumes bytes inside an OSC (title) sequence until the terminator
 - is found.
-}
dropOscBody :: [Word8] -> [Word8]
dropOscBody [] = []
dropOscBody (7 : xs) = xs -- BEL terminator
dropOscBody (27 : 92 : xs) = xs -- ESC \ terminator
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
control characters mapped for our 1D cursor emulation:
- 8  : Backspace
- 9  : Tab Expansion
- 10 : Newline
- 11 : Internal Clear-Line (\ESC[K)
- 12 : Internal Delete Char (\ESC[P)
- 13 : Carriage Return
- 14 : Internal Cursor Right (\ESC[C)
- 15 : Internal Cursor Left (\ESC[D)
- 16 : Internal Insert Space (\ESC[@)
-}
isSafePrintable :: Word8 -> Bool
isSafePrintable x =
    (x >= 32 && x <= 126)
        || x >= 128
        || x `elem` [8, 9, 10, 11, 12, 13, 14, 15, 16]
