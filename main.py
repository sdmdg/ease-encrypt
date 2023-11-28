"""
EaseEncrypt
Version 0.1.0

Author: Malaka D.Gunawardana.

Release Notes:
- Version 0.1.0 (Initial Release) (2023/11/28)

For Updates and Contributions:
    Visit the GitHub repository:
    - https://github.com/sdmdg/ease-encrypt

Report issues or contribute to the development. :)
"""

import os, sys
from PyQt5 import uic
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QLineEdit, QDialog
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from modules import encrypt, decrypt


class EaseEncrypt(QMainWindow):
    def __init__(self):
        super(EaseEncrypt, self).__init__()
        # Setup UI
        uic.loadUi(resource_path('data/main.ui'), self)
        self.setWindowIcon(QIcon(resource_path("./data/icon.png")))
        self.setWindowTitle("EaseEncrypt " + App_version)
        self.lbl_version.setText(f"v{App_version}")
        self.btn_e_input.clicked.connect(lambda: self.f_btn_openfile(mode="encrypt"))
        self.btn_d_input.clicked.connect(lambda: self.f_btn_openfile(mode="decrypt"))
        self.btn_e_output.clicked.connect(lambda: self.f_btn_savefile(mode="encrypt"))
        self.btn_d_output.clicked.connect(lambda: self.f_btn_savefile(mode="decrypt"))
        self.btn_clear.clicked.connect(self.f_btn_clear_inputs)
        self.btn_about.clicked.connect(self.f_btn_about)
        self.btn_encrypt.clicked.connect(self.f_btn_encrypt)
        self.btn_decrypt.clicked.connect(self.f_btn_decrypt)
        self.lbl_icon.setPixmap(QPixmap(resource_path("./data/main.png")))
        self.aniblock.setVisible(False)
        self.show()

    def f_btn_openfile(self, mode=""):
        options = QFileDialog.Options()
        files, _ = QFileDialog.getOpenFileNames(self, "Select file(s)", "", "All Files (*)", options=options)
        if not files:pass
        else:
            if mode == "encrypt":
                self.e_input.setText(";".join(files))
            else:
                self.d_input.setText(";".join(files))

    def f_btn_savefile(self, mode=""):
        options = QFileDialog.Options()
        dir = QFileDialog.getExistingDirectory(self, options=options)
        if not dir:pass
        else:
            if mode == "encrypt":
                self.e_output.setText(dir)
            else:
                self.d_output.setText(dir)

    def f_btn_clear_inputs(self):
        self.e_input.setText("")
        self.d_input.setText("")
        self.e_output.setText("")
        self.d_output.setText("")
        self.lbl_status.setText("Ready")

    def f_btn_about(self):
        dialog = sys_AboutDialog()
        dialog.exec()

    def f_btn_encrypt(self):
        queue = []

        if self.e_input.text() == "":
            self.lbl_status.setText("Enter input file(s)")
            return
        else:
            e_dir = self.e_output.text()
            if e_dir == "":
                self.lbl_status.setText("Enter a output directory")
                return
            else:
                if self.sys_chkdirs(path=e_dir, mode="dir"):
                    pass
                else:
                    self.lbl_status.setText(f"Error : {e_dir}")
                    return
            e_files = self.e_input.text().split(";")

            self.f_disable_all()
            for e_file in e_files:
                if self.sys_chkdirs(path=e_file, mode="file"):
                    queue.append(e_file)
                else:
                    dialog = SyS_InfoDialog(title="Error !!!", msg=f"{os.path.basename(e_file)} not found").exec_()
                    self.lbl_status.setText(f"{os.path.basename(e_file)} not found")
                    self.f_enable_all()
                    return
            dialog = SyS_InputDialog(title="Input password", msg="Input password: Min 6 characters", ispassword=True, password_confirm=True)
            result = dialog.exec_()
            if result == QDialog.Accepted:
                password = dialog.input.text()
                self.thread = CipherThread(password=password, input_files=queue, output_dir=e_dir, mode="encrypt")
                self.thread.finished.connect(self.f_enable_all)
                self.thread.start()
                return
            else:
                self.f_enable_all()
                return

    def f_btn_decrypt(self):
        queue = []

        if self.d_input.text() == "":
            self.lbl_status.setText("Enter input file(s)")
            return
        else:
            d_dir = self.d_output.text()
            if d_dir == "":
                self.lbl_status.setText("Enter a output directory")
                return
            else:
                if self.sys_chkdirs(path=d_dir, mode="dir"):
                    pass
                else:
                    self.lbl_status.setText(f"Error : {d_dir}")
                    return
            d_files = self.d_input.text().split(";")

            self.f_disable_all()
            for d_file in d_files:
                if self.sys_chkdirs(path=d_file, mode="file"):
                    queue.append(d_file)
                else:
                    dialog = SyS_InfoDialog(title="Error !!!", msg=f"{os.path.basename(d_file)} not found").exec_()
                    self.lbl_status.setText(f"{os.path.basename(d_file)} not found")
                    self.f_enable_all()
                    return
            dialog = SyS_InputDialog(title="Input password", msg="Input password:", ispassword=True, password_confirm=False)
            result = dialog.exec_()
            if result == QDialog.Accepted:
                password = dialog.input.text()
                self.thread = CipherThread(password=password, input_files=queue, output_dir=d_dir, mode="decrypt")
                self.thread.finished.connect(self.f_enable_all)
                self.thread.start()
                return
            else:
                self.f_enable_all()
                return

    def sys_chkdirs(self, path, mode = ""):
        # Check dirs and files
        if not os.path.exists(path):
            if mode == "file":
                return 0
            elif mode == "dir":
                try:
                    os.mkdir(str(path))
                    return 1
                except Exception as e :
                    dialog = SyS_InfoDialog(title="Error !!!", msg=str(e)).exec_()
                    return 0
        else:
            if mode == "file":
                if os.access(path, os.R_OK) == True: return 1
                else: return 0
            elif mode == "dir":
                if os.access(path, os.W_OK) == True: return 1
                else: return 0

    def f_disable_all(self):
        self.e_input.setEnabled(False)
        self.d_input.setEnabled(False)
        self.e_output.setEnabled(False)
        self.d_output.setEnabled(False)
        self.btn_clear.setEnabled(False)
        self.btn_encrypt.setEnabled(False)
        self.btn_decrypt.setEnabled(False)
        self.btn_e_input.setEnabled(False)
        self.btn_d_input.setEnabled(False)
        self.btn_e_output.setEnabled(False)
        self.btn_d_output.setEnabled(False)
        self.aniblock.setVisible(True)

    def f_enable_all(self):
        self.e_input.setEnabled(True)
        self.d_input.setEnabled(True)
        self.e_output.setEnabled(True)
        self.d_output.setEnabled(True)
        self.btn_clear.setEnabled(True)
        self.btn_encrypt.setEnabled(True)
        self.btn_decrypt.setEnabled(True)
        self.btn_e_input.setEnabled(True)
        self.btn_d_input.setEnabled(True)
        self.btn_e_output.setEnabled(True)
        self.btn_d_output.setEnabled(True)
        self.aniblock.setVisible(False)

class CipherThread(QThread):
    finished = pyqtSignal()
    def __init__(self, password, input_files, output_dir, mode=""):
        super().__init__()
        self.password = password
        self.input_files = input_files
        self.output_dir = output_dir
        self.mode = mode

    def run(self):
        if self.mode == "encrypt":
            for file in self.input_files:
                main_window.lbl_status.setText(f"Encrypting : {os.path.basename(file)}")
                try:
                    encrypt(password=self.password, input_file=file, output_file=(os.path.join(self.output_dir, os.path.basename(file)+".enc")))
                except:
                    main_window.lbl_status.setText(f"Error : {os.path.basename(file)} encryption faild. :(")
                    self.finished.emit()
                    return  
            main_window.lbl_status.setText(f"Encryption complete")
            self.finished.emit()
        else:
            for file in self.input_files:
                main_window.lbl_status.setText(f"Decrypting : {os.path.basename(file)}")
                try:
                    decrypt(password=self.password, input_file=file, output_file=(os.path.join(self.output_dir, os.path.basename(file)[:-4])))
                except:
                    main_window.lbl_status.setText(f"Error : {os.path.basename(file)} decryption faild. :(")
                    self.finished.emit()
                    return  
            main_window.lbl_status.setText(f"Decryption complete")
            self.finished.emit()

class SyS_InfoDialog(QDialog):   
    def __init__(self, parent=None, title="title", msg="msg"):
        super(SyS_InfoDialog, self).__init__(parent)
        # Display simple msg window
        self = uic.loadUi(resource_path('data/dlg_info.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(resource_path("./data/icon.png")))
        self.text.setText(msg)
        self.btn_ok.clicked.connect(self.accept)
        self.btn_ok.setDefault(True)
        self.show()

class SyS_InputDialog(QDialog):   
    def __init__(self, parent=None, title="title", msg="msg", msg2="Confirm password:", ispassword=False, password_confirm=False):
        super(SyS_InputDialog, self).__init__(parent)
        # Display the password window
        self = uic.loadUi(resource_path('data/dlg_input.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(resource_path("./data/icon.png")))
        self.text.setText(msg)
        if ispassword:
            self.input.setEchoMode(QLineEdit.Password)
            if password_confirm:
                self.btn_ok.setEnabled(False)
                self.text_2.setText(msg2)
                self.input_2.setEchoMode(QLineEdit.Password)

                self.input.textChanged.connect(self.chk_password)
                self.input_2.textChanged.connect(self.chk_password)
            else:
                self.input_2.setVisible(False)
                self.text_2.setVisible(False)
                self.setMinimumHeight(120)
                self.setMaximumHeight(120)
                self.btn_ok.setGeometry(130,80,75,23)
                self.btn_cancel.setGeometry(210,80,75,23)

        self.btn_ok.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)
        self.btn_ok.setDefault(True)
        self.show()

    def chk_password(self):
        if self.input.text() == self.input_2.text() and self.input.text()!= "" and len(self.input.text())>=6:
            self.btn_ok.setEnabled(True)
        else:
            self.btn_ok.setEnabled(False)

class sys_AboutDialog(QDialog):   
    def __init__(self, parent=None):
        super(sys_AboutDialog, self).__init__(parent)
        # Display the about window
        self = uic.loadUi(resource_path('data/dlg_about.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle("About")
        self.setWindowIcon(QIcon(resource_path("./data/icon.png")))
        self.dummy_3.setText(''.join(chr(ord(char) - 1) for char in "Efwfmpqfe!cz;!Nbmblb!E/Hvobxbsebob/"))
        self.lbl_name_and_version.setText("Name : EaseEncrypt\nVersion : " + App_version)
        pixmap = QPixmap(resource_path("./data/icon.png"))
        pixmap = pixmap.scaledToWidth(200, Qt.SmoothTransformation)
        self.icon.setPixmap(pixmap)
        self.btn_ok.clicked.connect(self.accept)
        self.btn_ok.setDefault(True)
        self.show()

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


# Main

if __name__ == '__main__':
    app = QApplication(sys.argv)
    working_directory = os.getcwd()
    # INFO
    App_version = "0.1.0"
    main_window = EaseEncrypt()
    
    sys.exit(app.exec_())