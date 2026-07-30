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
module Dassh.UI (drawUI, dasshAttrMap) where

import Brick
import Brick.Widgets.Border
import Brick.Widgets.Border.Style
import Brick.Widgets.Center
import Data.ByteString.Char8 qualified as BC
import Graphics.Vty qualified as V

import Dassh.Types (AppState (..), SshSession (..))

selectedAttr, unselectedAttr, titleAttr :: AttrName
selectedAttr = attrName "selected"
unselectedAttr = attrName "unselected"
titleAttr = attrName "title"

{- | Global attribute map defining the color scheme for the dashboard.
It applies Cyan to the currently focused session for instant visual feedback,
and bold Yellow to the border titles.
-}
dasshAttrMap :: AttrMap
dasshAttrMap =
    attrMap
        V.defAttr
        [ (selectedAttr, fg V.cyan)
        , (unselectedAttr, fg V.white)
        , (titleAttr, fg V.yellow `V.withStyle` V.bold)
        ]

{- | Main rendering function consumed by Brick.
The integer type parameter represents the resource name for viewports.
-}
drawUI :: AppState -> [Widget Int]
drawUI state
    | null (appSessions state) = [center $ str "No active SSH sessions discovered."]
    | appExpanded state = [drawExpanded (appSessions state !! appSelectedIdx state)]
    | otherwise = [drawGrid state]

{- | Draws a vertical grid containing all actively monitored sessions.
Applies the global border style and standard dashboard title.
-}
drawGrid :: AppState -> Widget Int
drawGrid state =
    let sessions = appSessions state
        selected = appSelectedIdx state
        widgets = zipWith (drawPane selected) [0 ..] sessions
     in withBorderStyle unicode $
            borderWithLabel (withAttr titleAttr $ str " dassh - Active Sessions ") $
                vBox widgets

{- | Draws an individual preview pane for a specific session.
It dynamically alters its border style and color based on focus state.
-}
drawPane :: Int -> Int -> SshSession -> Widget Int
drawPane selectedIdx currentIdx session =
    let isSelected = selectedIdx == currentIdx
        -- Unpack the ByteString TTY specifically for UI String rendering
        title = " PID: " ++ show (sessionPid session) ++ " (" ++ BC.unpack (sessionTty session) ++ ") "

        -- Determine visual distinction based on focus
        bStyle = if isSelected then unicodeBold else unicode
        paneAttr = if isSelected then selectedAttr else unselectedAttr
     in withAttr paneAttr $
            withBorderStyle bStyle $
                borderWithLabel (withAttr titleAttr $ str title) $
                    -- `padRight Max` acts as a greedy layout constraint.
                    -- It immediately forces every pane to consume 100%
                    -- of the horizontal terminal width, eliminating
                    -- staggering borders.
                    padAll 1 $
                        padRight Max $
                            let cleanText = BC.unpack $ sessionBuffer session
                                preview = unlines . reverse . take 6 . reverse . lines $ cleanText
                             in str preview

{- | Draws the selected session in full-screen with a scrollable viewport.
Forces the viewport to occupy 100% of both horizontal and vertical space.
-}
drawExpanded :: SshSession -> Widget Int
drawExpanded session =
    -- Unpack the ByteString TTY specifically for UI String rendering
    let title = " [EXPANDED] PID: " ++ show (sessionPid session) ++ " (" ++ BC.unpack (sessionTty session) ++ ") "
        cleanText = BC.unpack $ sessionBuffer session
     in withAttr selectedAttr $
            withBorderStyle unicodeBold $
                borderWithLabel (withAttr titleAttr $ str title) $
                    -- Constrain the viewport on Both axes, and use greedy
                    -- padding (Max) on the content to push the borders
                    -- to the absolute edges of the terminal.
                    viewport (sessionPid session) Both $
                        padAll 1 $
                            str cleanText
