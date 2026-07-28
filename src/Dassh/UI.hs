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
Module      : Dassh.UI
Description : Pure drawing logic for the Brick dashboard.

This module defines the layout and styling of the UI. It dynamically
renders a vertical grid of terminal panes or a full-screen detail view
with scrollback based on the application state.
-}
module Dassh.UI (drawUI) where

import Brick
import Brick.Widgets.Border
import Brick.Widgets.Border.Style
import Brick.Widgets.Center
import Data.ByteString.Char8 qualified as BC

import Dassh.Types (AppState (..), SshSession (..))

{- | Main rendering function consumed by Brick.
The integer type parameter represents the resource name for viewports.
-}
drawUI :: AppState -> [Widget Int]
drawUI state
    | null (appSessions state) = [center $ str "No active SSH sessions discovered."]
    | appExpanded state = [drawExpanded (appSessions state !! appSelectedIdx state)]
    | otherwise = [drawGrid state]

-- | Draws a vertical grid containing all actively monitored sessions.
drawGrid :: AppState -> Widget Int
drawGrid state =
    let sessions = appSessions state
        selected = appSelectedIdx state
        widgets = zipWith (drawPane selected) [0 ..] sessions
     in withBorderStyle unicode $
            borderWithLabel (str " dassh - Active Sessions ") $
                vBox widgets

-- | Draws an individual preview pane for a specific session.
drawPane :: Int -> Int -> SshSession -> Widget Int
drawPane selectedIdx currentIdx session =
    let isSelected = selectedIdx == currentIdx
        title = " PID: " ++ show (sessionPid session) ++ " (" ++ sessionTty session ++ ") "
        bStyle = if isSelected then unicodeBold else unicode
     in withBorderStyle bStyle $
            borderWithLabel (str title) $
                -- Show only the last 6 lines for the preview grid
                let cleanText = BC.unpack $ sessionBuffer session
                    preview = unlines . reverse . take 6 . reverse . lines $ cleanText
                 in padAll 1 $ str preview

-- | Draws the selected session in full-screen with a scrollable viewport.
drawExpanded :: SshSession -> Widget Int
drawExpanded session =
    let title = " [EXPANDED] PID: " ++ show (sessionPid session) ++ " (" ++ sessionTty session ++ ") "
        cleanText = BC.unpack $ sessionBuffer session
     in withBorderStyle unicodeBold $
            borderWithLabel (str title) $
                -- Use the session's PID as the unique Resource Name for
                -- the viewport. We use 'Both' axes instead of just
                -- 'Vertical' to constrain the text horizontally; otherwise,
                -- long strings will stretch the widget and push the
                -- right-hand border off the screen.
                viewport (sessionPid session) Both $
                    padAll 1 $
                        str cleanText
