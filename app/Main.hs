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
Module      : Main
Description : Application entry point and initialization lifecycle.

This module is responsible for bootstrapping dassh. It performs checks to
ensure root privileges, parses command-line arguments, executes the /proc
discovery phase, and sets up the execution flow for eBPF initialization.
-}
module Main (main) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Exception (bracket_)
import Control.Monad (forever, void, when)
import Options.Applicative
import System.Exit (die)
import System.Posix.User (getRealUserID)

import Brick.BChan (newBChan, writeBChan)
import Brick.Main (customMain)
import Graphics.Vty qualified as V
import Graphics.Vty.CrossPlatform (mkVty)

import Dassh.App (dasshApp)
import Dassh.Discovery (discoverSshSessions)
import Dassh.Ebpf (cleanupEbpf, initEbpf, startPollingThread, trackPid)
import Dassh.Types (AppState (..), DasshEvent (..), SshSession (..))

-- | CLI Configuration options
newtype AppConfig = AppConfig
    {verbose :: Bool}
    deriving (Show)

-- | Parser for command-line arguments using optparse-applicative
configParser :: Parser AppConfig
configParser =
    AppConfig
        <$> switch
            ( long "verbose"
                <> short 'v'
                <> help "Enable verbose logging for debugging"
            )

-- | Boilerplate to generate the CLI help menu
opts :: ParserInfo AppConfig
opts =
    info
        (configParser <**> helper)
        ( fullDesc
            <> progDesc "Start the dassh live SSH monitoring dashboard"
            <> header "dassh - zero-overhead eBPF SSH monitor"
        )

-- | Validates that the program is executing as the root user.
ensureRootPrivileges :: IO ()
ensureRootPrivileges = do
    uid <- getRealUserID
    when (uid /= 0) $
        die "Error: dassh MUST be run with root privileges (sudo)."

-- | Initializes the application state with discovered SSH sessions.
buildInitialState :: [SshSession] -> AppState
buildInitialState sessions =
    AppState
        { appSessions = sessions
        , appSelectedIdx = 0
        , appExpanded = False
        }

-- | Main execution flow
main :: IO ()
main = do
    config <- execParser opts
    ensureRootPrivileges

    when (verbose config) $ putStrLn "[INFO] Starting dassh in verbose mode..."
    putStrLn "[INFO] Root privileges confirmed."

    -- /proc Discovery
    putStrLn "[INFO] Scanning /proc for active SSH sessions..."
    activeSessions <- discoverSshSessions
    let state = buildInitialState activeSessions

    putStrLn $ "[INFO] Discovered " ++ show (length (appSessions state)) ++ " active SSH session(s)."
    when (verbose config) $
        mapM_ (putStrLn . ("       - " ++) . show) (appSessions state)

    -- Trigger Global eBPF Load & Attach UI
    putStrLn "[INFO] Loading eBPF program into kernel..."

    bracket_ initEbpf cleanupEbpf $ do
        -- Immediately track initially discovered sessions!
        mapM_ (trackPid . sessionPid) activeSessions

        -- Create a Brick communication channel bounded to 1000 events
        eventChan <- newBChan 1000

        -- Start the eBPF polling thread. It writes raw payloads
        -- directly to the Brick channel.
        let onEvent e = writeBChan eventChan (NewPayload e)
        _ <- startPollingThread onEvent

        -- Start the background dynamic discovery thread
        _ <- forkIO $ forever $ do
            threadDelay (2 * 1000000) -- Wait 2 seconds
            sessions <- discoverSshSessions

            -- Dynamically track new sessions as users log in
            mapM_ (trackPid . sessionPid) sessions
            writeBChan eventChan (RefreshSessions sessions)

        -- Initialize VTY and hand execution over to the Brick event loop.
        -- 'bracket_' safely guarantees 'cleanupEbpf' fires when Brick halts.
        initialVty <- mkVty V.defaultConfig
        void $ customMain initialVty (mkVty V.defaultConfig) (Just eventChan) dasshApp state

    putStrLn "[INFO] Clean shutdown complete."
