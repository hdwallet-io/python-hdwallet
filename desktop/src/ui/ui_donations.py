# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'donationsXuevSI.ui'
##
## Created by: Qt User Interface Compiler version 6.5.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QComboBox, QFrame, QHBoxLayout,
    QLabel, QPushButton, QSizePolicy, QSpacerItem,
    QVBoxLayout, QWidget)

class Ui_Form(object):
    def setupUi(self, Form):
        if not Form.objectName():
            Form.setObjectName(u"Form")
        Form.resize(512, 414)
        self.FormVLayout = QVBoxLayout(Form)
        self.FormVLayout.setSpacing(0)
        self.FormVLayout.setObjectName(u"FormVLayout")
        self.FormVLayout.setContentsMargins(0, 5, 0, 0)
        self.donationsNavbarQFrame = QFrame(Form)
        self.donationsNavbarQFrame.setObjectName(u"donationsNavbarQFrame")
        self.donationsNavbarQFrameHLayout = QHBoxLayout(self.donationsNavbarQFrame)
        self.donationsNavbarQFrameHLayout.setSpacing(10)
        self.donationsNavbarQFrameHLayout.setObjectName(u"donationsNavbarQFrameHLayout")
        self.donationsNavbarQFrameHLayout.setContentsMargins(10, 0, 0, 0)
        self.donationsQLabel = QLabel(self.donationsNavbarQFrame)
        self.donationsQLabel.setObjectName(u"donationsQLabel")

        self.donationsNavbarQFrameHLayout.addWidget(self.donationsQLabel)

        self.donationsNavbarQFrameHSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.donationsNavbarQFrameHLayout.addItem(self.donationsNavbarQFrameHSpacer)

        self.donationsQPushButtonContainerQFrame = QFrame(self.donationsNavbarQFrame)
        self.donationsQPushButtonContainerQFrame.setObjectName(u"donationsQPushButtonContainerQFrame")
        self.donationsQPushButtonContainerQFrame.setFrameShape(QFrame.StyledPanel)
        self.donationsQPushButtonContainerQFrame.setFrameShadow(QFrame.Raised)
        self.donationsQPushButtonContainerQFrameHLayout = QHBoxLayout(self.donationsQPushButtonContainerQFrame)
        self.donationsQPushButtonContainerQFrameHLayout.setSpacing(0)
        self.donationsQPushButtonContainerQFrameHLayout.setObjectName(u"donationsQPushButtonContainerQFrameHLayout")
        self.donationsQPushButtonContainerQFrameHLayout.setContentsMargins(0, 0, 0, 0)

        self.donationsNavbarQFrameHLayout.addWidget(self.donationsQPushButtonContainerQFrame)

        self.closeModalButtonQFrame = QFrame(self.donationsNavbarQFrame)
        self.closeModalButtonQFrame.setObjectName(u"closeModalButtonQFrame")
        self.closeModalButtonQFrame.setMinimumSize(QSize(35, 25))
        self.closeModalButtonQFrame.setMaximumSize(QSize(35, 25))
        self.closeModalButtonQFrame.setFrameShape(QFrame.StyledPanel)
        self.closeModalButtonQFrame.setFrameShadow(QFrame.Raised)
        self.closeModalButtonQFrameVLayout = QVBoxLayout(self.closeModalButtonQFrame)
        self.closeModalButtonQFrameVLayout.setSpacing(0)
        self.closeModalButtonQFrameVLayout.setObjectName(u"closeModalButtonQFrameVLayout")
        self.closeModalButtonQFrameVLayout.setContentsMargins(0, 0, 0, 0)

        self.donationsNavbarQFrameHLayout.addWidget(self.closeModalButtonQFrame)


        self.FormVLayout.addWidget(self.donationsNavbarQFrame)

        self.donationsPageQFrame = QFrame(Form)
        self.donationsPageQFrame.setObjectName(u"donationsPageQFrame")
        self.donationsCoreTeamQWidgetVLayout = QVBoxLayout(self.donationsPageQFrame)
        self.donationsCoreTeamQWidgetVLayout.setSpacing(5)
        self.donationsCoreTeamQWidgetVLayout.setObjectName(u"donationsCoreTeamQWidgetVLayout")
        self.donationsCoreTeamQWidgetVLayout.setContentsMargins(0, 10, 0, 20)
        self.donationsCoreTeamQRQFrame = QFrame(self.donationsPageQFrame)
        self.donationsCoreTeamQRQFrame.setObjectName(u"donationsCoreTeamQRQFrame")
        self.donationsCoreTeamQRQFrameHLayout = QHBoxLayout(self.donationsCoreTeamQRQFrame)
        self.donationsCoreTeamQRQFrameHLayout.setSpacing(0)
        self.donationsCoreTeamQRQFrameHLayout.setObjectName(u"donationsCoreTeamQRQFrameHLayout")
        self.donationsCoreTeamQRQFrameHLayout.setContentsMargins(0, 0, 0, 0)
        self.donationsCoreTeamQRCodeQFrame = QFrame(self.donationsCoreTeamQRQFrame)
        self.donationsCoreTeamQRCodeQFrame.setObjectName(u"donationsCoreTeamQRCodeQFrame")
        self.donationsCoreTeamQRCodeQFrameHLayout = QHBoxLayout(self.donationsCoreTeamQRCodeQFrame)
        self.donationsCoreTeamQRCodeQFrameHLayout.setSpacing(0)
        self.donationsCoreTeamQRCodeQFrameHLayout.setObjectName(u"donationsCoreTeamQRCodeQFrameHLayout")
        self.donationsCoreTeamQRCodeQFrameHLayout.setContentsMargins(0, 0, 0, 0)
        self.donationsCoreTeamQRCodeQFrameVLSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.donationsCoreTeamQRCodeQFrameHLayout.addItem(self.donationsCoreTeamQRCodeQFrameVLSpacer)

        self.donationQRCodeContainerQFrame = QFrame(self.donationsCoreTeamQRCodeQFrame)
        self.donationQRCodeContainerQFrame.setObjectName(u"donationQRCodeContainerQFrame")
        self.donationQRCodeContainerQFrameVLayout = QVBoxLayout(self.donationQRCodeContainerQFrame)
        self.donationQRCodeContainerQFrameVLayout.setSpacing(0)
        self.donationQRCodeContainerQFrameVLayout.setObjectName(u"donationQRCodeContainerQFrameVLayout")
        self.donationQRCodeContainerQFrameVLayout.setContentsMargins(0, 0, 0, 0)
        self.donationsQRCodeQLabel = QLabel(self.donationQRCodeContainerQFrame)
        self.donationsQRCodeQLabel.setObjectName(u"donationsQRCodeQLabel")
        self.donationsQRCodeQLabel.setMinimumSize(QSize(200, 200))
        self.donationsQRCodeQLabel.setMaximumSize(QSize(200, 200))

        self.donationQRCodeContainerQFrameVLayout.addWidget(self.donationsQRCodeQLabel)


        self.donationsCoreTeamQRCodeQFrameHLayout.addWidget(self.donationQRCodeContainerQFrame)

        self.donationsCoreTeamQRCodeQFrameVRSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.donationsCoreTeamQRCodeQFrameHLayout.addItem(self.donationsCoreTeamQRCodeQFrameVRSpacer)


        self.donationsCoreTeamQRQFrameHLayout.addWidget(self.donationsCoreTeamQRCodeQFrame)


        self.donationsCoreTeamQWidgetVLayout.addWidget(self.donationsCoreTeamQRQFrame)

        self.donationsCoreTeamQWidgetVTSpacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.donationsCoreTeamQWidgetVLayout.addItem(self.donationsCoreTeamQWidgetVTSpacer)

        self.donationComboContainersQFrame = QFrame(self.donationsPageQFrame)
        self.donationComboContainersQFrame.setObjectName(u"donationComboContainersQFrame")
        self.donationComboContainersQFrame.setFrameShape(QFrame.StyledPanel)
        self.donationComboContainersQFrame.setFrameShadow(QFrame.Raised)
        self.donationComboContainersQFrameHLayout = QHBoxLayout(self.donationComboContainersQFrame)
        self.donationComboContainersQFrameHLayout.setSpacing(15)
        self.donationComboContainersQFrameHLayout.setObjectName(u"donationComboContainersQFrameHLayout")
        self.donationComboContainersQFrameHLayout.setContentsMargins(0, 0, 0, 0)
        self.donationComboContainersQFrameHLSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.donationComboContainersQFrameHLayout.addItem(self.donationComboContainersQFrameHLSpacer)

        self.donationVComboContainerQFrame = QFrame(self.donationComboContainersQFrame)
        self.donationVComboContainerQFrame.setObjectName(u"donationVComboContainerQFrame")
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.donationVComboContainerQFrame.sizePolicy().hasHeightForWidth())
        self.donationVComboContainerQFrame.setSizePolicy(sizePolicy)
        self.donationVComboContainerQFrame.setMinimumSize(QSize(300, 0))
        self.donationVComboContainerQFrame.setMaximumSize(QSize(300, 16777215))
        self.donationVComboContainerQFrame.setFrameShape(QFrame.StyledPanel)
        self.donationVComboContainerQFrame.setFrameShadow(QFrame.Raised)
        self.donationVComboContainerQFrameVLayout = QVBoxLayout(self.donationVComboContainerQFrame)
        self.donationVComboContainerQFrameVLayout.setSpacing(15)
        self.donationVComboContainerQFrameVLayout.setObjectName(u"donationVComboContainerQFrameVLayout")
        self.donationVComboContainerQFrameVLayout.setContentsMargins(0, 0, 0, 0)
        self.donationsCoreTeamAddressQFrame = QFrame(self.donationVComboContainerQFrame)
        self.donationsCoreTeamAddressQFrame.setObjectName(u"donationsCoreTeamAddressQFrame")
        self.donationsCoreTeamAddressQFrameHLayout = QHBoxLayout(self.donationsCoreTeamAddressQFrame)
        self.donationsCoreTeamAddressQFrameHLayout.setSpacing(15)
        self.donationsCoreTeamAddressQFrameHLayout.setObjectName(u"donationsCoreTeamAddressQFrameHLayout")
        self.donationsCoreTeamAddressQFrameHLayout.setContentsMargins(0, 0, 0, 0)
        self.donationsAddressQLabel = QLabel(self.donationsCoreTeamAddressQFrame)
        self.donationsAddressQLabel.setObjectName(u"donationsAddressQLabel")
        self.donationsAddressQLabel.setAlignment(Qt.AlignCenter)
        self.donationsAddressQLabel.setIndent(0)

        self.donationsCoreTeamAddressQFrameHLayout.addWidget(self.donationsAddressQLabel)

        self.donationsAddressCopyQPushButton = QPushButton(self.donationsCoreTeamAddressQFrame)
        self.donationsAddressCopyQPushButton.setObjectName(u"donationsAddressCopyQPushButton")
        self.donationsAddressCopyQPushButton.setMinimumSize(QSize(75, 0))
        self.donationsAddressCopyQPushButton.setMaximumSize(QSize(75, 16777215))
        self.donationsAddressCopyQPushButton.setCursor(QCursor(Qt.PointingHandCursor))

        self.donationsCoreTeamAddressQFrameHLayout.addWidget(self.donationsAddressCopyQPushButton)


        self.donationVComboContainerQFrameVLayout.addWidget(self.donationsCoreTeamAddressQFrame)

        self.donationsCoreTeamCryptocurrencyQFrame = QFrame(self.donationVComboContainerQFrame)
        self.donationsCoreTeamCryptocurrencyQFrame.setObjectName(u"donationsCoreTeamCryptocurrencyQFrame")
        self.donationsCoreTeamCryptocurrencyQFrame.setMinimumSize(QSize(150, 0))
        self.donationsCoreTeamCryptocurrencyQFrameVLayout = QVBoxLayout(self.donationsCoreTeamCryptocurrencyQFrame)
        self.donationsCoreTeamCryptocurrencyQFrameVLayout.setSpacing(15)
        self.donationsCoreTeamCryptocurrencyQFrameVLayout.setObjectName(u"donationsCoreTeamCryptocurrencyQFrameVLayout")
        self.donationsCoreTeamCryptocurrencyQFrameVLayout.setContentsMargins(0, 0, 0, 0)
        self.donationsCryptocurrencyQLabel = QLabel(self.donationsCoreTeamCryptocurrencyQFrame)
        self.donationsCryptocurrencyQLabel.setObjectName(u"donationsCryptocurrencyQLabel")

        self.donationsCoreTeamCryptocurrencyQFrameVLayout.addWidget(self.donationsCryptocurrencyQLabel, 0, Qt.AlignHCenter)

        self.donationsCryptocurrencyQComboBox = QComboBox(self.donationsCoreTeamCryptocurrencyQFrame)
        self.donationsCryptocurrencyQComboBox.setObjectName(u"donationsCryptocurrencyQComboBox")
        self.donationsCryptocurrencyQComboBox.setCursor(QCursor(Qt.PointingHandCursor))

        self.donationsCoreTeamCryptocurrencyQFrameVLayout.addWidget(self.donationsCryptocurrencyQComboBox)


        self.donationVComboContainerQFrameVLayout.addWidget(self.donationsCoreTeamCryptocurrencyQFrame)

        self.donationsCaptionQLabel = QLabel(self.donationVComboContainerQFrame)
        self.donationsCaptionQLabel.setObjectName(u"donationsCaptionQLabel")

        self.donationVComboContainerQFrameVLayout.addWidget(self.donationsCaptionQLabel)


        self.donationComboContainersQFrameHLayout.addWidget(self.donationVComboContainerQFrame)

        self.donationComboContainersQFrameHRSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.donationComboContainersQFrameHLayout.addItem(self.donationComboContainersQFrameHRSpacer)


        self.donationsCoreTeamQWidgetVLayout.addWidget(self.donationComboContainersQFrame)


        self.FormVLayout.addWidget(self.donationsPageQFrame)


        self.retranslateUi(Form)

        QMetaObject.connectSlotsByName(Form)
    # setupUi

    def retranslateUi(self, Form):
        Form.setWindowTitle(QCoreApplication.translate("Form", u"Form", None))
        self.donationsQLabel.setText(QCoreApplication.translate("Form", u"Donations", None))
        self.donationsQRCodeQLabel.setText(QCoreApplication.translate("Form", u"QR Code", None))
        self.donationsAddressQLabel.setText(QCoreApplication.translate("Form", u"Address", None))
        self.donationsAddressCopyQPushButton.setText(QCoreApplication.translate("Form", u"Copy", None))
        self.donationsCryptocurrencyQLabel.setText(QCoreApplication.translate("Form", u"Cryptocurrency", None))
        self.donationsCryptocurrencyQComboBox.setPlaceholderText(QCoreApplication.translate("Form", u"Select Cryptocurrency", None))
        self.donationsCaptionQLabel.setText(QCoreApplication.translate("Form", u"Caption", None))
    # retranslateUi

