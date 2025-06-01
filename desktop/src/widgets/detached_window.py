#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from PySide6.QtWidgets import (
    QWidget, QFrame, QPlainTextEdit
)
from PySide6.QtCore import (
    QEvent, QRect, Qt
)

class DetachedTerminalWindow(QWidget):
    """
    A custom widget representing a detached window.
    """

    def __init__(self, p: QWidget) -> None:
        """
        Initialize the DetachedWindow instance.

        :param p: The parent widget.
        :type p: QWidget
        """
        super().__init__()
        self.main_window = p

    def closeEvent(self, event) -> None:
        """
        Handle the close event of the detached window.

        :param event: The close event.
        """
        self.main_window.ui.toggle_expand_terminal.setChecked(False)
        self.main_window.toggle_expand(False)

    def center_window(self) -> None:
        """
        Center the detached window on the screen.
        """
        screen = self.screen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
