#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from functools import lru_cache
from PIL.ImageQt import ImageQt, Image

import os
import qrcode

from PySide6.QtSvg import QSvgRenderer

from PySide6.QtWidgets import (
    QWidget, QLayout, QLabel
)
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QPixmap, QPainter

from hdwallet.mnemonics import ElectrumV2Mnemonic


def clear_layout(layout: QLayout, delete: bool = True) -> None:
    """
    Clear all widgets from a layout.

    :param layout: The layout to clear.
    :param delete: Whether to delete the widgets after removing them from the layout.
    """
    if layout is not None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None and delete:
                widget.deleteLater()
            else:
                clear_layout(item.layout())


def resolve_path(path: str) -> str:
    """
    Resolve the absolute path of a given relative path.

    :param path: The relative path to resolve.
    :type path: str
    :return: The absolute path of the given relative path.
    :rtype: str
    """
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "../../", path))


def render_svg_on_label(label, svg_path):
    """
    Renders an SVG image on a given QLabel.

    :param label: QLabel object where the SVG image will be rendered.
    :type label: QLabel
    :param svg_path: The file path to the SVG image.
    :type svg_path: str

    :returns: None
    """

    svg_renderer = QSvgRenderer(svg_path)
    pixmap = QPixmap(180, 180)
    pixmap.fill(Qt.white)
    painter = QPainter(pixmap)
    svg_renderer.render(painter)
    painter.end()
    label.setPixmap(pixmap)


def put_svg(layout: QLayout, path: str, width: int, height: int) -> QSvgWidget:
    """
    Add an SVG widget to a layout.

    :param layout: The layout to add the SVG widget to.
    :param path: The path to the SVG file.
    :param width: The width of the SVG widget.
    :param height: The height of the SVG widget.
    :return: The SVG widget.
    """
    clear_layout(layout)
    svg = QSvgWidget(path)
    svg.setMinimumSize(QSize(width, height))
    svg.setMaximumSize(QSize(width, height))
    svg.setStyleSheet("background: transparent")
    layout.addWidget(svg)
    return svg


def put_qr_code(qr_label: QLabel, text: str) -> None:
        """
        Generate and display a QR code.

        :param qr_label: The QLabel to display the QR code.
        :param text: The text data to encode in the QR code.
        """
        qr_label.setText(None)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(text)
        qr.make(fit=True)

        img = qr.make_image(
            fill_color="white",
            back_color="#191e24"
        )

        qimage = ImageQt(img)

        pixmap = QPixmap.fromImage(qimage)

        qr_label.setPixmap(pixmap)
        qr_label.setAlignment(Qt.AlignCenter)
        qr_label.setScaledContents(True)


def update_style(widget: QWidget) -> None:
    """
    Update the style of a widget.

    :param widget: The widget to update the style for.
    """
    widget.setStyleSheet(widget.styleSheet())


def update_border_class(widget: QWidget, border_style: str) -> None:
    """
    Sets a red border on the given widget by adding a 'red-border' class to its properties.

    :param widget: The widget to which the red border class is applied.
    """
    widget.setProperty("class", border_style)
    widget.style().unpolish(widget)
    widget.style().polish(widget)

def clear_borders_class(group_boxes: list):
    """
    Clears the borders from all widgets in the provided group by removing the 'red-border' class.

    :param group_boxes: A list of widgets from which the 'red-border' class is removed.
    """
    for widget in group_boxes:
        widget.setProperty("class", "")
        widget.style().unpolish(widget)
        widget.style().polish(widget)

@lru_cache(maxsize=1)
def normalized_mnemonic_types() -> list:
    formatted_items = []
    for item in ElectrumV2Mnemonic.mnemonic_types.keys():
        parts = item.split('-')
        formatted_item = '-'.join([part.capitalize() if idx == 0 else part.upper() for idx, part in enumerate(parts)])
        formatted_items.append(formatted_item)
    return formatted_items
