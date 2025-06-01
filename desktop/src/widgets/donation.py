#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit
import os

from PySide6.QtWidgets import (
    QWidget, QFrame, QVBoxLayout, QLabel, QPushButton
)
from PySide6.QtCore import (
    Qt, QSize, QTimer
)
from PySide6.QtGui import (
    QIcon, QCursor
)

from src.widgets.modal import Modal
from src.ui.ui_donations import Ui_Form
from src.addresses import crypto_addresses
from src.utils import put_qr_code, resolve_path
from src.utils.clipboard import copy_to_clipboard


class Donation(Modal):
    """
    Donation modal implementation
    """
    def __init__(self, parent, parent_frame) -> None:
        """
        Initialize the Donation frame.
        """
        super(Donation, self).__init__(parent, parent_frame)
        self.ui: Optional[Ui_Form] = None

    def core_crypto_changed(self) -> None:
        """
        Update the core team donation address and QR code when the selected cryptocurrency changes.
        """
        for crypto in crypto_addresses:
            self.ui.donationsCryptocurrencyQComboBox.addItem(crypto["cryptocurrency"])

        selected_crypto = self.ui.donationsCryptocurrencyQComboBox.currentText()
        crypto_details = next((item for item in crypto_addresses if item["cryptocurrency"] == selected_crypto), None)

        addr = crypto_details["address"]
        self.core_addr = addr

        self.ui.donationsAddressQLabel.setText(f"{addr[:10]}...{addr[-9:]}")
        put_qr_code(self.ui.donationsQRCodeQLabel, addr)
        


    def copy_address(self) -> None:
        """
        Copy the address to clipboard, change button text to 'Copied' for 1 second, and then revert.
        """
        copy_to_clipboard(text=self.core_addr, frame=self)
        
        self.ui.donationsAddressCopyQPushButton.setText("Copied")
        self.ui.donationsAddressCopyQPushButton.setEnabled(False)

        QTimer.singleShot(1000, self.reset_copy_button)

    def reset_copy_button(self) -> None:
        """
        Reset the copy button text back to 'Copy' and enable it.
        """
        self.ui.donationsAddressCopyQPushButton.setText("Copy")
        self.ui.donationsAddressCopyQPushButton.setEnabled(True)


    @staticmethod
    def show_donation_modal(main_window: QWidget, parent_frame: QWidget) -> None:
        """
        Display the donation frame within the given main window.

        :param main_window: The main application window.
        :param parent_frame: Modal parent frame
        """
        frame: Donation = Donation(parent=main_window, parent_frame=parent_frame)

        main_widget = QWidget()
        main_widget.setContentsMargins(0, 0, 0, 0)
        donation_ui = Ui_Form()
        donation_ui.setupUi(main_widget)
        frame.ui = donation_ui

        close_icon = QIcon(resolve_path("src/ui/images/svg/close.svg"))

        frame.close_button = QPushButton(None)
        frame.close_button.setIcon(close_icon)
        frame.close_button.setIconSize(QSize(12, 12))
        frame.close_button.clicked.connect(frame.close)
        frame.close_button.setCursor(QCursor(Qt.PointingHandCursor))
        donation_ui.closeModalButtonQFrame.layout().addWidget(frame.close_button)


        donation_ui.donationsCryptocurrencyQComboBox.addItems(
            sorted([crypto['cryptocurrency'] for crypto in crypto_addresses])
        )
        donation_ui.donationsCryptocurrencyQComboBox.currentIndexChanged.connect(frame.core_crypto_changed)
        donation_ui.donationsCryptocurrencyQComboBox.setCurrentText("Ethereum")

        donation_ui.donationsCaptionQLabel.setTextFormat(Qt.RichText)
        donation_ui.donationsCaptionQLabel.setText(
            """Your donation empowers our core team to continue our work and grow. Every contribution counts—thank you for your support!"""
        )

        donation_ui.donationsCaptionQLabel.setWordWrap(True)

        donation_ui.donationsAddressCopyQPushButton.clicked.connect(frame.copy_address)

        frame.layout().addWidget(main_widget)
        frame.re_adjust()
        frame.show()
