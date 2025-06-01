#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import os
import re
import json
from typing import (
    Optional, Union
)

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QStackedWidget, QVBoxLayout, QLayout
)
from PySide6.QtCore import (
    Qt, QEvent, QThreadPool, QSize,
    QRect, QFileSystemWatcher, QObject
)
from PySide6.QtGui import (
    QFontDatabase, QIcon,
    QTextCharFormat, QTextCursor, QColor
)

from src.info import __version__ as desktop_version
from hdwallet.info import __version__ as library_version

from src.utils import (
    put_svg, update_style, resolve_path
)
from src.ui.ui_hdwallet import Ui_MainWindow
from src.widgets.detached_window import DetachedTerminalWindow

class Application(QMainWindow):
    _instance: Optional['Application'] = None
    ui: Ui_MainWindow = None
    detached_window: DetachedTerminalWindow = None
    fs_watcher: QFileSystemWatcher = None

    TEXT_COLOR: QColor = QColor(255, 255, 255)
    HIGHLIGHT_PATTERN = [
        (re.compile(r'^ERROR'), QColor(255, 96, 96)),                                  # ERROR
        (re.compile(r'^WARNING'), QColor(255, 221, 0)),                                # WARNING
        (re.compile(r'\bm/.*?(?=\s)'), QColor(131, 185, 255)),                         # "m/" path
        (re.compile(r'\".*?\"(?=\s*:)'), QColor(131, 185, 255)),                       # keys
        (re.compile(r'\".*?\"'), QColor(255, 255, 255)),                               # string
        (re.compile(r'(?<=[\[\s])\d+(?=,|\]|$)'), QColor(255, 165, 0)),                # numbers
        (re.compile(r'(?<=[\[\s])(true|false|null)(?=,|\]|$)'), QColor(255, 165, 0)),  # boolean/null
        (re.compile(r'[{}[\],:]'), QColor(255, 255, 255))                              # punctuation
    ]

    def __new__(cls, *args, **kwargs) -> 'Application':
        """
        Create a new instance if not already created, implementing the Singleton pattern.
        """
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """
        Initialize the Application instance if not already initialized.
        """
        if not hasattr(self, 'initialized'):
            super().__init__()
            self.initialize()
            self.initialized = True

    @classmethod
    def instance(cls) -> 'Application':
        """
        Get the singleton instance of the Application.

        :return: The singleton instance of Application.
        """
        if not cls._instance:
            cls._instance = cls()
        return cls._instance

    def initialize(self) -> None:
        """
        Perform initialization tasks for the application, such as setting up the UI and loading resources.
        """
        QThreadPool.globalInstance().setMaxThreadCount(64)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.detached_window = None

        self.setWindowTitle("Hierarchical Deterministic Wallet")
        self.hdwallet_icon = QIcon(resolve_path("src/ui/images/icon/icon.ico"))
        self.setWindowIcon(self.hdwallet_icon)
        css_path = resolve_path("src/ui/css/theme.css")
        self.fs_watcher = QFileSystemWatcher([css_path])
        self.fs_watcher.fileChanged.connect(lambda: self.load_stylesheet(css_path))
        self.load_stylesheet(css_path)
        put_svg(
            self.ui.hdwalletLogoHLayout,
            resolve_path("src/ui/images/svg/hdwalletLogoFullSize.svg"),
            132.04,
            45
        )
    
        QFontDatabase.addApplicationFont(resolve_path("src/ui/font/HDWallet.ttf"))


        self.resize_evt = ResizeEventFilter()
        self.resize_evt.resize_event_callback = self.update_terminal_ui
        self.ui.outputQFrame.installEventFilter(self.resize_evt)
        self.ui.outputTerminalQPlainTextEdit.verticalScrollBar().rangeChanged.connect(self.update_terminal_ui)

        versions = {
            "library": library_version,
            "desktop": desktop_version
        }
        self.ui.outputTerminalQPlainTextEdit.setPlaceholderText(json.dumps(versions, indent=4))

    def load_stylesheet(self, path: str) -> None:
        """
        Load and apply a stylesheet from the specified path.

        :param path: The path to the stylesheet file.
        """
        try:
            with open(path, 'r', encoding='utf-8') as style_file:
                stylesheet = style_file.read()
                self.setStyleSheet(stylesheet)
        except Exception as e:
            print(f"Failed to load stylesheet: {e}")

    def tab_changed(self, stacked_name: str, page_name: str, button: QWidget, qWidget: QWidget) -> None:
        """
        Handle custom tab changes, updating the active button and changing the displayed page.

        :param stacked_name: The name of the QStackedWidget.
        :param page_name: The name of the page to display.
        :param button: The button widget that was clicked.
        :param qWidget: The parent widget containing the buttons.
        """
        for btn in qWidget.findChildren(QWidget):
            btn.setProperty("Active", "")
            update_style(btn)

        button.setProperty("Active", "true")
        update_style(button)
        self.change_page(stacked_name, page_name)

    def change_page(self, stacked_name: str, widget_name: str) -> None:
        """
        Change the currently displayed page in a QStackedWidget.

        :param stacked_name: The name of the QStackedWidget.
        :param widget_name: The name of the widget to display.
        """
        qStackedWidget: Optional[QStackedWidget] = self.findChild(QStackedWidget, stacked_name)

        if qStackedWidget is None:
            print(f"QStackWidget not found: {stacked_name}")
            return

        qWidget: Optional[QWidget] = qStackedWidget.findChild(QWidget, widget_name)

        if qStackedWidget and qWidget:
            qStackedWidget.setCurrentWidget(qWidget)
        else:
            print(f"ERROR changing page: '{stacked_name}' '{widget_name}'")

    def println(self, data: Optional[Union[str, dict]], end="\n") -> None:
        """
        Print a message to the terminal UI.

        :param data: The message to print. Can be a dictionary, string, or None.
        """

        if isinstance(data, dict):
            data = json.dumps(data, indent=4, ensure_ascii=False)
        elif data is None:
            return

        cursor = self.ui.outputTerminalQPlainTextEdit.textCursor()
        cursor.movePosition(QTextCursor.End)

        default_format = QTextCharFormat()
        default_format.setForeground(Application.TEXT_COLOR)

        # Group all edits into a single operation
        cursor.beginEditBlock()

        for line in data.splitlines():
            pos = 0
            matches = []
            matched_ranges = []

            # Collect all matches for the line, avoiding overlaps
            for pattern, color in Application.HIGHLIGHT_PATTERN:
                for match in pattern.finditer(line):
                    start, end_pos = match.start(), match.end()
                    # Check if this match overlaps with any existing matched ranges
                    overlaps = False
                    for m_start, m_end in matched_ranges:
                        if start < m_end and end_pos > m_start:
                            overlaps = True
                            break
                    if not overlaps:
                        matches.append((start, end_pos, color, match.group()))
                        matched_ranges.append((start, end_pos))

            # Sort matches by start position
            matches.sort(key=lambda x: x[0])

            # Insert text with formatting
            while pos < len(line):
                # Check if there's a match starting at the current position
                if matches and matches[0][0] == pos:
                    start, end_pos, color, text = matches.pop(0)
                    cformat = QTextCharFormat()
                    cformat.setForeground(color)
                    cursor.insertText(text, cformat)
                    pos = end_pos
                else:
                    # Insert unformatted text up to the next match or end of line
                    next_match_start = matches[0][0] if matches else len(line)
                    cursor.insertText(line[pos:next_match_start], default_format)
                    pos = next_match_start
            cursor.insertText(end, default_format)  # Newline or other end character

        cursor.endEditBlock()

        # Update the cursor and ensure it's visible
        self.ui.outputTerminalQPlainTextEdit.setTextCursor(cursor)
        self.ui.outputTerminalQPlainTextEdit.ensureCursorVisible()

    def toggle_expand(self, detach: bool) -> None:
        """
        Toggle the expansion of the terminal window, either detaching it or reattaching it to the main window.

        :param detach: Whether to detach the terminal window.
        """
        if detach:
            self.setMaximumSize(
                self.ui.hdWalletContainerQFrame.width(), self.ui.hdwalletMainQFrame.height()
            )
            self.setWindowFlag(Qt.WindowMaximizeButtonHint, False)
            self.showNormal()

            self.layout().removeWidget(self.ui.outputQFrame)
            self.detached_window = DetachedTerminalWindow(self)
            self.detached_window.setWindowTitle("Terminal")
            self.detached_window.setWindowIcon(self.hdwallet_icon)
            self.detached_window.resize(self.ui.outputQFrame.width(), self.ui.outputQFrame.height())
            self.detached_window.setMinimumHeight(self.minimumHeight())

            layout = QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.ui.outputQFrame)

            self.detached_window.setLayout(layout)
            self.detached_window.show()
            self.detached_window.setStyleSheet(self.styleSheet())
            self.setMinimumWidth(0)
            self.detached_window.center_window()

            if not self.isMaximized():
                self.resize(self.width() - self.ui.outputQFrame.width(), self.height())

        else:
            if self.detached_window:
                self.detached_window.close()
                self.detached_window = None

            self.ui.centralwidget.layout().addWidget(self.ui.outputQFrame)


            self.setMaximumSize(16777215, 16777215)
            self.ui.outputQFrame.setGeometry(QRect(
                0, 0, 600, self.ui.outputQFrame.height()
            ))
            self.setWindowFlag(Qt.WindowMaximizeButtonHint, True)
            self.show()

    def closeEvent(self, event: QEvent) -> None:
        """
        Handle the close event, ensuring any detached windows are closed.

        :param event: The close event.
        """
        if self.detached_window:
            self.detached_window.close()
        super().closeEvent(event)

    def update_terminal_ui(self) -> None:
        """
        Update the layout of the terminal UI elements.
        """
        self.ui.outputWidgetTopContainerQWidget.setGeometry(QRect(
            (
                self.ui.noLayoutQWidget.width() - (
                    self.ui.outputWidgetTopContainerQFrame.width() + (
                        20 if self.ui.outputTerminalQPlainTextEdit.verticalScrollBar().maximum() > 0 else 10
                    )
                )
            ), 0,
            self.ui.outputWidgetTopContainerQFrame.width(), self.ui.outputWidgetTopContainerQWidget.height()
        ))
        self.ui.outputTerminalQWidget.setGeometry(QRect(
            0, 0, self.ui.noLayoutQWidget.width(), self.ui.noLayoutQWidget.height()
        ))
        self.ui.outputWidgetTopContainerQWidget.raise_()

    def show(self) -> None:
        """
        Override the show method to update the terminal UI when the window is shown.
        """
        super(Application, self).show()
        self.update_terminal_ui()


class ResizeEventFilter(QObject):
    resize_event_callback = None
    def eventFilter(self, obj, event):
        if event.type() == QEvent.Resize:
            if self.resize_event_callback != None:
                self.resize_event_callback()
        return super().eventFilter(obj, event)
