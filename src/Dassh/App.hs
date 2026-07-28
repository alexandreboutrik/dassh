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
Module      : Dassh.App
Description : Application state wiring and event handlers.

This module integrates the pure UI drawing logic with Brick's event loop.
It handles user keybindings (Tab, Enter, q) and processes custom events
injected by the eBPF polling thread.
-}
module Dassh.App (dasshApp) where

import Brick
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import Graphics.Vty qualified as V

import Control.Monad (when)

import Dassh.Sanitize (applyTerminalState, isCompletionGarbage, sanitizePayload)
import Dassh.Types (AppState (..), DasshEvent (..), EbpfEvent (..), SshSession (..))
import Dassh.UI (drawUI)

-- | The core Brick application definition.
dasshApp :: App AppState DasshEvent Int
dasshApp =
    App
        { appDraw = drawUI
        , appChooseCursor = neverShowCursor
        , appHandleEvent = handleEvent
        , appStartEvent = return ()
        , appAttrMap = const $ attrMap V.defAttr []
        }

-- | Modifies the AppState purely based on standard and custom events.
handleEvent :: BrickEvent Int DasshEvent -> EventM Int AppState ()
handleEvent (VtyEvent (V.EvKey (V.KChar 'q') [])) = halt
handleEvent (VtyEvent (V.EvKey (V.KChar '\t') [])) = modify cycleFocus
handleEvent (VtyEvent (V.EvKey V.KEnter [])) = modify toggleExpanded
-- Scrolling events for the expanded viewport
handleEvent (VtyEvent (V.EvKey V.KUp [])) = scrollExpanded (-1)
handleEvent (VtyEvent (V.EvKey V.KDown [])) = scrollExpanded 1
handleEvent (VtyEvent (V.EvKey V.KPageUp [])) = scrollPageExpanded Up
handleEvent (VtyEvent (V.EvKey V.KPageDown [])) = scrollPageExpanded Down
handleEvent (VtyEvent (V.EvMouseDown _ _ V.BScrollUp [])) = scrollExpanded (-3)
handleEvent (VtyEvent (V.EvMouseDown _ _ V.BScrollDown [])) = scrollExpanded 3
handleEvent (AppEvent (NewPayload event)) = do
    -- Update the state with the new payload
    modify (updateSessionBuffer event)

    -- Trigger Auto-Scroll if the updated session is currently expanded
    state <- get
    let targetPid = fromIntegral (eventRootPid event)
    when (appExpanded state && not (null (appSessions state))) $ do
        let selectedPid = sessionPid (appSessions state !! appSelectedIdx state)
        when (selectedPid == targetPid) $ do
            vScrollToEnd (viewportScroll selectedPid)
handleEvent (AppEvent (RefreshSessions latest)) = modify (syncSessions latest)
handleEvent _ = return ()

-- | Helper to scroll the viewport by exact lines
scrollExpanded :: Int -> EventM Int AppState ()
scrollExpanded amt = do
    state <- get
    when (appExpanded state && not (null (appSessions state))) $ do
        let pid = sessionPid (appSessions state !! appSelectedIdx state)
        -- Fetch the viewport by PID and scroll it
        vScrollBy (viewportScroll pid) amt

-- | Helper to scroll the viewport by full pages
scrollPageExpanded :: Direction -> EventM Int AppState ()
scrollPageExpanded dir = do
    state <- get
    when (appExpanded state && not (null (appSessions state))) $ do
        let pid = sessionPid (appSessions state !! appSelectedIdx state)
        -- Fetch the viewport by PID and scroll by a full page
        vScrollPage (viewportScroll pid) dir

-- | Moves the focus to the next pane in the dashboard.
cycleFocus :: AppState -> AppState
cycleFocus state
    | null (appSessions state) = state
    | otherwise = state {appSelectedIdx = (appSelectedIdx state + 1) `mod` length (appSessions state)}

-- | Toggles the full-screen view for the currently focused pane.
toggleExpanded :: AppState -> AppState
toggleExpanded state = state {appExpanded = not (appExpanded state)}

{- | Appends the sanitized payload to the session buffer.
If the payload originates from the Root Bash's internal pipe (fd 1), it is
line-buffered in 'sessionStaging' to prevent chunk fragmentation before running
the heuristic autocomplete filter. Terminal redraws (fd 2) pass through instantly.
-}
updateSessionBuffer :: EbpfEvent -> AppState -> AppState
updateSessionBuffer event state =
    let targetRootPid = fromIntegral (eventRootPid event)
        actualPid = eventActualPid event
        fd = eventFd event
        safeData = sanitizePayload (eventPayload event)

        updateSession s
            | sessionPid s == targetRootPid && not (BS.null safeData) =
                let isRootBashFd1 = (actualPid == eventRootPid event) && (fd == 1)
                    (newBuf, newCursor, newStaging) =
                        if isRootBashFd1
                            then
                                -- Line-Buffer pipes to prevent chunk fragmentation
                                let combined = BS.append (sessionStaging s) safeData
                                    (ready, rest) = BS.breakEnd (== 10) combined
                                    -- Filter garbage on complete lines only
                                    linesToProcess =
                                        BS.intercalate (BS.pack [10]) $
                                            filter (not . isCompletionGarbage) $
                                                BC.split '\n' ready
                                    (b, c) = applyTerminalState (sessionBuffer s) (sessionCursor s) linesToProcess
                                 in (b, c, rest)
                            else
                                -- Terminal redraws (fd 2) or child utilities stream directly
                                let (b, c) = applyTerminalState (sessionBuffer s) (sessionCursor s) safeData
                                 in (b, c, sessionStaging s)

                    trimmed =
                        if BS.length newBuf > 16384
                            then BS.drop (BS.length newBuf - 16384) newBuf
                            else newBuf
                 in s {sessionBuffer = trimmed, sessionCursor = newCursor, sessionStaging = newStaging}
            | otherwise = s
     in state {appSessions = map updateSession (appSessions state)}

{- | Cleanly merges newly discovered sessions without erasing existing
 - output buffers.
It also drops sessions that have disconnected and prevents index
out-of-bounds errors.
-}
syncSessions :: [SshSession] -> AppState -> AppState
syncSessions latest state =
    let current = appSessions state

        -- Keep current sessions (preserving their buffers) if they are
        -- still active
        stillActive = filter (\c -> any (\l -> sessionPid l == sessionPid c) latest) current

        -- Find entirely new sessions that just logged in
        isNew l = not $ any (\c -> sessionPid c == sessionPid l) current
        newSessions = filter isNew latest

        merged = stillActive ++ newSessions

        -- Ensure selected index stays within bounds if users disconnect
        safeIdx = if null merged then 0 else min (appSelectedIdx state) (length merged - 1)
        safeExpanded = appExpanded state && not (null merged)
     in state
            { appSessions = merged
            , appSelectedIdx = safeIdx
            , appExpanded = safeExpanded
            }
