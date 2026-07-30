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
import Data.IntSet qualified as IS
import Graphics.Vty qualified as V

import Control.Monad (when)

import Dassh.Sanitize (applyTerminalState, isCompletionGarbage, sanitizePayload)
import Dassh.Types (AppState (..), DasshEvent (..), EbpfEvent (..), SshSession (..), Zipper (..), zipperFromList, zipperMap, zipperNext, zipperToList)
import Dassh.UI (dasshAttrMap, drawUI)

-- | The core Brick application definition.
dasshApp :: App AppState DasshEvent Int
dasshApp =
    App
        { appDraw = drawUI
        , appChooseCursor = neverShowCursor
        , appHandleEvent = handleEvent
        , appStartEvent = return ()
        , appAttrMap = const dasshAttrMap
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
    case appSessions state of
        Just z | appExpanded state -> do
            let selectedPid = sessionPid (zFocus z)
            when (selectedPid == targetPid) $ do
                vScrollToEnd (viewportScroll selectedPid)
        _ -> return ()
handleEvent (AppEvent (RefreshSessions latest)) = modify (syncSessions latest)
handleEvent _ = return ()

-- | Helper to scroll the viewport by exact lines
scrollExpanded :: Int -> EventM Int AppState ()
scrollExpanded amt = do
    state <- get
    case appSessions state of
        Just z | appExpanded state -> do
            let pid = sessionPid (zFocus z)
            vScrollBy (viewportScroll pid) amt
        _ -> return ()

-- | Helper to scroll the viewport by full pages
scrollPageExpanded :: Direction -> EventM Int AppState ()
scrollPageExpanded dir = do
    state <- get
    case appSessions state of
        Just z | appExpanded state -> do
            let pid = sessionPid (zFocus z)
            vScrollPage (viewportScroll pid) dir
        _ -> return ()

-- | Moves the focus to the next pane in the dashboard.
cycleFocus :: AppState -> AppState
cycleFocus state = state {appSessions = fmap zipperNext (appSessions state)}

-- | Toggles the full-screen view for the currently focused pane.
toggleExpanded :: AppState -> AppState
toggleExpanded state = state {appExpanded = not (appExpanded state)}

{- | Line-buffers stdout pipes to prevent chunk fragmentation.
Filters out internal Bash autocomplete garbage on complete lines only.
Returns the filtered complete lines and the remaining uncompleted fragment.
-}
processLineBufferedOutput :: BS.ByteString -> BS.ByteString -> (BS.ByteString, BS.ByteString)
processLineBufferedOutput currentStaging newData =
    let combined = BS.append currentStaging newData
        (ready, rest) = BS.breakEnd (== 10) combined

        -- Split on newline, filter out garbage, and re-join the lines
        filteredLines =
            BS.intercalate (BS.pack [10])
                . filter (not . isCompletionGarbage)
                $ BC.split '\n' ready
     in (filteredLines, rest)

-- | Maximum size of the terminal scrollback buffer in bytes (16KB).
maxScrollbackSize :: Int
maxScrollbackSize = 16384

{- | Pure helper to trim the session buffer and prevent infinite
memory growth.
-}
trimBuffer :: BS.ByteString -> BS.ByteString
trimBuffer buf
    | BS.length buf > maxScrollbackSize = BS.drop (BS.length buf - maxScrollbackSize) buf
    | otherwise = buf

{- | Appends the sanitized payload to the session buffer.
If the payload originates from the Root Bash's internal pipe (fd 1), it
routes to 'processLineBufferedOutput' to handle fragmentation and filtering.
Terminal redraws (fd 2) or child utilities bypass this and stream directly
to the UI.
-}
updateSessionBuffer :: EbpfEvent -> AppState -> AppState
updateSessionBuffer event state =
    let targetRootPid = fromIntegral (eventRootPid event)
        isRootBashFd1 = (eventActualPid event == eventRootPid event) && (eventFd event == 1)

        updateSession s
            -- Guard clause: ignore if this session isn't the target
            | sessionPid s /= targetRootPid = s
            | otherwise =
                let (newTuiMode, newAntiStaging, safeData) = sanitizePayload (sessionInTuiMode s) (sessionAnsiStaging s) (eventPayload event)

                    (dataToRender, newStaging) =
                        if isRootBashFd1
                            then processLineBufferedOutput (sessionStaging s) safeData
                            else (safeData, sessionStaging s)

                    (newBuf, newCursor) =
                        if BS.null dataToRender
                            then (sessionBuffer s, sessionCursor s)
                            else applyTerminalState (sessionBuffer s) (sessionCursor s) dataToRender
                 in s
                        { sessionBuffer = trimBuffer newBuf
                        , sessionCursor = newCursor
                        , sessionStaging = newStaging
                        , sessionInTuiMode = newTuiMode
                        , sessionAnsiStaging = newAntiStaging
                        }
     in state {appSessions = fmap (zipperMap updateSession) (appSessions state)}

{- | Cleanly merges newly discovered sessions without erasing existing
 - output buffers.
It also drops sessions that have disconnected and prevents index
out-of-bounds errors.
-}
syncSessions :: [SshSession] -> AppState -> AppState
syncSessions latest state =
    let currentList = maybe [] zipperToList (appSessions state)
        oldFocusedPid = fmap (sessionPid . zFocus) (appSessions state)

        -- Create fast O(log N) lookup sets for PIDs
        latestPids = IS.fromList $ map sessionPid latest
        currentPids = IS.fromList $ map sessionPid currentList

        -- Keep current sessions (preserving their buffers) if they are
        -- still present in the latest discovery poll
        stillActive = filter (\c -> sessionPid c `IS.member` latestPids) currentList

        -- Find entirely new sessions that just logged in
        newSessions = filter (\l -> not (sessionPid l `IS.member` currentPids)) latest

        mergedList = stillActive ++ newSessions

        -- Reconstruct the zipper and attempt to restore previous focus
        newZipper = case zipperFromList mergedList of
            Nothing -> Nothing
            Just z -> Just (restoreFocus oldFocusedPid z)

        safeExpanded = appExpanded state && not (null mergedList)
     in state
            { appSessions = newZipper
            , appExpanded = safeExpanded
            }

-- | Helper to restore focus to a specific PID after synchronization
restoreFocus :: Maybe Int -> Zipper SshSession -> Zipper SshSession
restoreFocus Nothing z = z
restoreFocus (Just pid) z =
    let lst = zipperToList z
        (prev, rest) = break (\s -> sessionPid s == pid) lst
     in case rest of
            [] -> z -- PID not found (disconnected), fallback to the head
            (f : next) -> Zipper (reverse prev) f next
