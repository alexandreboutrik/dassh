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
Module      : Dassh.Discovery
Description : Dynamic discovery of active SSH sessions via /proc scanning.

This module traverses the /proc filesystem to inspect running processes.
It reads the 'environ' file of each process, safely extracting the
'SSH_TTY' environment variable to identify active user shells before
the eBPF monitoring begins. This ensures the dashboard is pre-populated
on startup.
-}
module Dassh.Discovery (
    discoverSshSessions,
) where

import Control.Exception (IOException, try)
import Control.Monad (filterM)
import Data.ByteString (ByteString)
import Data.ByteString.Char8 qualified as BC
import Data.List (find)
import Data.Maybe (catMaybes, mapMaybe)
import System.Directory (doesDirectoryExist, listDirectory)
import System.FilePath ((</>))
import Text.Read (readMaybe)

import Dassh.Types (SshSession (..))

{- |
Main entry point to discover all active SSH sessions on the system.
It scans the /proc directory, filters for purely numeric directory
names (which represent valid PIDs), and attempts to extract SSH
metadata from each one.
-}
discoverSshSessions :: IO [SshSession]
discoverSshSessions = do
    let procDir = "/proc"
    entries <- listDirectory procDir

    -- Filter the directory list to keep only valid numeric PIDs
    let pids = mapMaybe readMaybe entries :: [Int]

    -- Prevent race conditions by ensuring the directory still exists.
    -- Processes can terminate rapidly between `listDirectory` and
    -- our inspection.
    validPids <- filterM (\pid -> doesDirectoryExist (procDir </> show pid)) pids

    -- Map over valid PIDs and filter out only the ones containing an SSH_TTY
    maybeSessions <- mapM checkPidForSsh validPids
    return $ catMaybes maybeSessions

{- |
Safely attempts to read a process's environment file to determine if it is
an active SSH shell. It gracefully handles permission errors or processes
that die during the read operation.
-}
checkPidForSsh :: Int -> IO (Maybe SshSession)
checkPidForSsh pid = do
    let commFile = "/proc" </> show pid </> "comm"

    -- We use 'try' to catch IOExceptions. Even as root, kernel threads or
    -- rapidly exiting processes will throw permission or EOF errors here.
    commResult <- try (BC.readFile commFile) :: IO (Either IOException ByteString)

    case commResult of
        Left _ -> return Nothing
        Right commData -> do
            let comm = BC.strip commData
            -- Only discover standard shells as root SSH sessions.
            -- This prevents child tools (like Nvim LSP servers) from
            -- being falsely identified as new logins.
            if comm `notElem` [BC.pack "bash", BC.pack "zsh", BC.pack "ash", BC.pack "sh", BC.pack "mksh", BC.pack "ksh"]
                then return Nothing
                else do
                    let envFile = "/proc" </> show pid </> "environ"
                    result <- try (BC.readFile envFile) :: IO (Either IOException ByteString)

                    case result of
                        Left _ -> return Nothing
                        Right envData ->
                            case extractSshTty envData of
                                Nothing -> return Nothing
                                Just tty ->
                                    return $
                                        Just
                                            SshSession
                                                { sessionPid = pid
                                                , sessionTty = tty
                                                , sessionBuffer = BC.empty
                                                , sessionCursor = 0
                                                , sessionStaging = BC.empty
                                                , sessionInTuiMode = False
                                                , sessionAnsiStaging = BC.empty
                                                -- for the UI
                                                }

{- |
Pure function to parse the raw, binary /proc/<pid>/environ file.
The Linux kernel formats this file by separating environment variables
with a null byte ('\0'). We split the ByteString on nulls to find the
specific TTY string.
-}
extractSshTty :: ByteString -> Maybe ByteString
extractSshTty envData = do
    -- Split the binary environment block by null terminators
    let envVars = BC.split '\0' envData
        prefix = BC.pack "SSH_TTY="

    -- Locate the exact variable declaration starting with "SSH_TTY="
    match <- find (BC.isPrefixOf prefix) envVars

    -- Strip the prefix and return the raw ByteString safely
    return $ BC.drop (BC.length prefix) match
