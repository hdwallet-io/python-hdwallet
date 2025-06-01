#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, List
)

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QLineEdit, QWidget
)

class HistoryLineEdit(QLineEdit):
    """
    A QLineEdit widget that maintains a history of inputted text and allows
    navigation through the history using the Up and Down arrow keys.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """
        Initialize a HistoryLineEdit instance.

        :param parent: Optional parent widget.
        :type parent: QWidget, optional
        """
        super().__init__(parent)
        self.history: List[str] = []
        self.history_index: int = 0

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """
        Handle key press events to navigate through input history.

        :param event: The key press event.
        :type event: QKeyEvent
        """
        if event.key() == Qt.Key_Up:
            self.prev()
        elif event.key() == Qt.Key_Down:
            self.next()
        elif event.key() == Qt.Key_Return:
            self.history.append(self.text())
            self.history_index = len(self.history)

        super().keyPressEvent(event)

    def prev(self) -> None:
        """
        Navigate to the previous item in input history.
        """
        if self.history_index > 0:
            self.history_index -= 1
            self.setText(self.history[self.history_index])

    def next(self) -> None:
        """
        Navigate to the next item in input history or clear the line edit if no more history items.
        """
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.setText(self.history[self.history_index])
        else:
            self.clear()
