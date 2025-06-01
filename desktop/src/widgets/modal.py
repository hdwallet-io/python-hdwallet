#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout
)
from PySide6.QtCore import (
    QEvent, Qt, Signal
)


class OverlayFrame(QFrame):
    """
    A custom QFrame that emits a clicked signal when pressed.
    """
    clicked = Signal()

    def mousePressEvent(self, event: QEvent) -> None:
        """
        Override the mousePressEvent to emit a clicked signal.

        :param event: The mouse press event.
        """
        if event.button() == Qt.LeftButton:
            self.clicked.emit()


class Modal(QFrame):
    """
    A custom modal implementation.
    """
    def __init__(self, parent, parent_frame) -> None:
        """
        Initialize the Modal frame.
        """
        super(Modal, self).__init__(parent)
        QVBoxLayout(self)

        self.margin: int = 15
        self.width: int = 418
        self.height: int = 508

        self.parent_frame = parent_frame
        self.overlay_frame: OverlayFrame = OverlayFrame(self.parent())
        self.overlay_frame.setStyleSheet("background-color: rgba(0, 0, 0, 128);")
        self.overlay_frame.clicked.connect(self.close)

        self.parent_frame.installEventFilter(self)
        self.setObjectName("modalQFrame")

    def re_adjust(self) -> None:
        """
        Re-adjust the frame and overlay positions.
        """
        parent_rect = self.parent().rect()
        geo = self.parent_frame.geometry()
        geo.setHeight(geo.height())

        x_pos = geo.width() / 2 - self.width / 2
        y_pos = geo.height() / 2 - self.height / 2
        y_pos -= self.height * 0.05
        self.setGeometry(x_pos, y_pos, self.width, self.height)

        self.overlay_frame.setGeometry(0, 0, geo.width(), geo.height())

    def eventFilter(self, obj: QFrame, event: QEvent) -> bool:
        """
        Override the event filter to handle resize events.

        :param obj: The object being filtered.
        :param event: The event being filtered.
        :return: True if the event should be filtered out, False otherwise.
        """
        if event.type() == QEvent.Resize:
            self.re_adjust()
        return super().eventFilter(obj, event)

    def show(self) -> None:
        """
        Override the show method to display the overlay frame and re-adjust the layout.
        """
        self.overlay_frame.show()
        self.raise_()
        super().show()

    def closeEvent(self, event: QEvent) -> None:
        """
        Handle the close event, deleting the overlay frame.

        :param event: The close event.
        """
        self.overlay_frame.deleteLater()
        self.deleteLater()