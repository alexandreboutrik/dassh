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

import Dassh.Types (AppState (..), SshSession (..), Zipper (..))

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
drawUI state = case appSessions state of
    Nothing -> [center $ str "No active SSH sessions discovered."]
    Just z
        | appExpanded state -> [drawExpanded (zFocus z)]
        | otherwise -> [drawGrid z]

{- | Draws a vertical grid containing all actively monitored sessions.
Applies the global border style and standard dashboard title.
-}
drawGrid :: Zipper SshSession -> Widget Int
drawGrid z =
    let widgets =
            map (drawPane False) (reverse $ zPrev z)
                ++ [drawPane True (zFocus z)]
                ++ map (drawPane False) (zNext z)
     in withBorderStyle unicode $
            borderWithLabel (withAttr titleAttr $ str " dassh - Active Sessions ") $
                vBox widgets

{- | Draws an individual preview pane for a specific session.
It dynamically alters its border style and color based on focus state.
-}
drawPane :: Bool -> SshSession -> Widget Int
drawPane isSelected session =
    let
        -- Unpack the ByteString TTY specifically for UI String rendering
        title = " PID: " ++ show (sessionPid session) ++ " (" ++ BC.unpack (sessionTty session) ++ ") "

        -- Determine visual distinction based on focus
        bStyle = if isSelected then unicodeBold else unicode
        paneAttr = if isSelected then selectedAttr else unselectedAttr
     in
        withAttr paneAttr $
            withBorderStyle bStyle $
                borderWithLabel (withAttr titleAttr $ str title) $
                    -- `padRight Max` acts as a greedy layout constraint.
                    -- It immediately forces every pane to consume 100%
                    -- of the horizontal terminal width, eliminating
                    -- staggering borders.
                    padAll 1 $
                        padRight Max $
                            if sessionInTuiMode session
                                then center $ str "[ Interactive TUI Active - Output Paused ]"
                                else
                                    let cleanText = BC.unpack $ sessionBuffer session
                                        preview = unlines . reverse . take 6 . reverse . lines $ cleanText
                                     in str preview

{- | Draws the selected session in full-screen with a scrollable viewport.
Forces the viewport to occupy 100% of both horizontal and vertical space.
Bypasses the viewport entirely if the session is in TUI mode to prevent
greedy widget (center) layout crashes in Brick.
-}
drawExpanded :: SshSession -> Widget Int
drawExpanded session =
    -- Unpack the ByteString TTY specifically for UI String rendering
    let title = " [EXPANDED] PID: " ++ show (sessionPid session) ++ " (" ++ BC.unpack (sessionTty session) ++ ") "
        cleanText = BC.unpack $ sessionBuffer session
     in withAttr selectedAttr $
            withBorderStyle unicodeBold $
                borderWithLabel (withAttr titleAttr $ str title) $
                    if sessionInTuiMode session
                        -- Render directly without a viewport if output is paused
                        then center $ str "[ Interactive TUI Active - Output Paused ]"
                        else
                            -- Constrain the viewport on Both axes, and use
                            -- greedy padding (Max) on the content to push
                            -- the borders to the absolute edges of
                            -- the terminal.
                            viewport (sessionPid session) Both $
                                padAll 1 $
                                    str cleanText
