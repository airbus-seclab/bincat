# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'hexview/hexview.ui'
#
# Created by: PyQt5 UI code generator 5.5
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(400, 300)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout.setObjectName("verticalLayout")
        self.mainLayout = QtWidgets.QVBoxLayout()
        self.mainLayout.setObjectName("mainLayout")
        self.statusLabel = QtWidgets.QLabel(Form)
        self.statusLabel.setMaximumSize(QtCore.QSize(16777215, 15))
        self.statusLabel.setObjectName("statusLabel")
        self.mainLayout.addWidget(self.statusLabel)
        self.verticalLayout.addLayout(self.mainLayout)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.statusLabel.setText(_translate("Form", "TextLabel"))

