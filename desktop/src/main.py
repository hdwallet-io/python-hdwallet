#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from PySide6.QtCore import (
    QThreadPool, QRegularExpression, Slot, Qt, QSize, QUrl
)
from PySide6.QtWidgets import (
    QSizePolicy, QWidget, QPushButton, QLineEdit, QPushButton
)
from PySide6.QtGui import (
    QRegularExpressionValidator, QCursor, QDesktopServices
)
from click.testing import CliRunner
from hdwallet.cli.__main__ import cli_main

import os
import re
import shlex
import functools

from src.utils import resolve_path
from src.widgets.core import *
from src.widgets.donation import Donation
from src.utils.worker import Worker
from src.generate import Generate
from src.dumps import Dumps
from src.utils import clear_borders_class

class MainApplication:
    """
    Main application class for managing the UI and core functionalities.
    """
    def __init__(self) -> None:
        """
        Initialize the MainApplication class.
        """
        super().__init__()

        self.app = Application.instance()
        self.ui = self.app.ui
        self.cli_runner = CliRunner()

        self.__init_ui()

    def __init_ui(self) -> None:
        """
        Initialize the UI components and their connections.
        """
        self.errboxes = [
            self.ui.dumpsStackQGroupBox,
            self.ui.derivationQGroupBox,
            self.ui.dumpsFormatKeysContainerQGroupBox,
            self.ui.generateClientAndStrengthContainerQGroupBox,
            self.ui.generateMnemonicClientWordsLanguageContainerQGroupBox,
            self.ui.seedGroupBoxContainerQGroupBox,
            self.ui.generateLengthAndPassphraseQGroupBox
        ]

        self.terminal_expand_icon = QIcon(resolve_path("src/ui/images/svg/expand-white-thin.svg"))
        self.terminal_collapse_icon = QIcon(resolve_path("src/ui/images/svg/collapse-white-thin.svg"))

        self.ui.toggle_expand_terminal = QPushButton(None)
        self.ui.toggle_expand_terminal.setCheckable(True)
        self.ui.toggle_expand_terminal.setChecked(False)
        self.ui.toggle_expand_terminal.setIcon(self.terminal_expand_icon)
        self.ui.toggle_expand_terminal.setIconSize(QSize(20, 20))

        self.ui.toggle_expand_terminal.setCursor(QCursor(Qt.PointingHandCursor))
        self.ui.toggle_expand_terminal.toggled.connect(self._toggle_terminal)

        self.ui.expandAndCollapseTerminalQFrame.layout().addWidget(self.ui.toggle_expand_terminal)

        self.ui.outputTerminalQLineEdit.textChanged.connect(
            lambda s: self.ui.outputTerminalQPushButton.setEnabled(s != "")
        )
        self.ui.outputTerminalQPushButton.setEnabled(False)

        self.ui.outputTerminalQLineEdit.returnPressed.connect(self.process_command)
        self.ui.outputTerminalQPushButton.clicked.connect(self.process_command)

        self.ui.clearTerminalQPushButton.clicked.connect(self._clear_terminal_and_borders)

        self._setup_tab_buttons()
        self.ui.dumpQPushButton.click()

        self.ui.donationHDWalletQPushButton.clicked.connect(
            lambda: Donation.show_donation_modal(
                main_window=self.app.window(), parent_frame=self.ui.hdWalletContainerQFrame
            )
        )

        self.ui.generateClientAndStrengthContainerQGroupBox.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.ui.generateSeedMnemonicContainerQFrame.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.ui.generateLengthContainerQFrame.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.ui.helpHDWalletQPushButton.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://talonlab.gitbook.io/hdwallet/manual/generate"))
        )
        self.ui.websiteQLabel.mousePressEvent = lambda event: QDesktopServices.openUrl(QUrl("https://hdwallet.io"))

        inputs = [
            self.ui.bip44AccountQLineEdit,
            self.ui.bip44AddressQLineEdit,
            self.ui.bip49AccountQLineEdit,
            self.ui.bip49AddressQLineEdit,
            self.ui.bip84AccountQLineEdit,
            self.ui.bip84AddressQLineEdit,
            self.ui.bip86AccountQLineEdit,
            self.ui.bip86AddressQLineEdit,
            self.ui.cip1852AccountQLineEdit,
            self.ui.cip1852AddressQLineEdit,
            self.ui.electrumChangeQLineEdit,
            self.ui.electrumAddressQLineEdit,
            self.ui.moneroMinorQLineEdit,
            self.ui.moneroMajorQLineEdit,
            self.ui.hdwAccountQLineEdit,
            self.ui.hdwAddressQLineEdit
        ]
        self.__validate_inputs(inputs)

        self.generate = Generate(self.app)
        self.dumps = Dumps(self.app)


    def _setup_tab_buttons(self):
        """
        Connects buttons to the generate_dump_tab_changed function and clears borders when the tab changes.
        """
        def on_tab_button_clicked(page_name, button):
            clear_borders_class(self.errboxes) 
            self.generate_dump_tab_changed(page_name, button)

        self.ui.generateQPushButton.clicked.connect(
            functools.partial(on_tab_button_clicked, "generatePageQStackedWidget", self.ui.generateQPushButton)
        )
        self.ui.dumpQPushButton.clicked.connect(
            functools.partial(on_tab_button_clicked, "dumpsPageQStackedWidget", self.ui.dumpQPushButton)
        )


    def _clear_terminal_and_borders(self):
        """
        Clears the terminal and resets borders for error boxes.

        :param self: Instance of the class, providing access to UI elements.
        """
        self.ui.outputTerminalQPlainTextEdit.clear()
        clear_borders_class(self.errboxes)

    def __validate_inputs(self, line_edits: list) -> None:
        """
        Validate and filter input fields for line edits.

        :param line_edits: A list of QLineEdit widgets to validate.
        """
        def validate_and_filter(input_string: str) -> Optional[str]:
            pattern = r'^\d-\d(?!-)$'
            return input_string if re.match(pattern, input_string) else None

        @Slot()
        def text_changed_callback(line_edit: QLineEdit) -> None:
            def callback() -> None:
                input_text = line_edit.text()
                filtered_text = validate_and_filter(input_text)
                if filtered_text is None:
                    line_edit.setValidator(QRegularExpressionValidator(QRegularExpression("[0-9]+-[0-9]+(?!-)")))
                else:
                    line_edit.setValidator(None)

            callback()

        for line_edit in line_edits:
            line_edit.textChanged.connect(text_changed_callback(line_edit))

    def process_command(self) -> None:
        """
        Process the command entered in the terminal input.
        """
        cmd = self.ui.outputTerminalQLineEdit.text().removeprefix('hdwallet ')
        self.ui.outputTerminalQLineEdit.setText(None)

        def process() -> str:
            commands = shlex.split(cmd)

            if any(word in commands for word in ("ds", "dumps")):
                return "WARNING: The 'dumps' command is not supported in the Desktop CLI. Please use the standalone CLI to perform this operation."

            cli = self.cli_runner.invoke(
                cli_main, commands, prog_name="hdwallet"
            )
            return cli.output

        if cmd.lower() == 'clear':
            self.ui.outputTerminalQPlainTextEdit.clear()
            self.ui.outputTerminalQLineEdit.setText(None)
        else:
            job = Worker(process)
            job.signals.interval_finished.connect(self.app.println)
            QThreadPool.globalInstance().start(job)

    def generate_dump_tab_changed(self, page_name: str, qPushButton: QPushButton) -> None:
        """
        Handle the tab change between generate and dump pages.

        :param page_name: The name of the page to switch to.
        :param qPushButton: The QPushButton that was clicked.
        """
        widget = self.ui.generateAndDumpTabContainerQFrame
        self.app.tab_changed("hdwalletQStackedWidget", page_name, qPushButton, widget)

    def _toggle_terminal(self) -> None:
        """
        Toggles terminal expand/collapse (detach/attach)
        """
        state = self.ui.toggle_expand_terminal.isChecked()
        icon = self.terminal_collapse_icon if state else self.terminal_expand_icon
        self.ui.toggle_expand_terminal.setIcon(icon)
        self.app.toggle_expand(state)