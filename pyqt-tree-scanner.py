#!/opt/homebrew/bin/python3
import os
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import squarify
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QComboBox, QVBoxLayout, QWidget, QPushButton, QFileDialog
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt, QThread
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class SecureDeleteThread(QThread):
    def __init__(self, file_path, method, passes):
        super().__init__()
        self.file_path = file_path
        self.method = method
        self.passes = passes

    def run(self):
        if self.method == 'zero':
            self.zero_fill()
        elif self.method == 'random':
            self.random_fill()
        elif self.method == 'dod':
            self.dod_standard()
        elif self.method == 'aes':
            self.aes_wipe()
        os.remove(self.file_path)

    def zero_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(b'\x00' * os.path.getsize(self.file_path))

    def random_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def dod_standard(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(3):  # DoD 5220.22-M standard is 3 passes
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def aes_wipe(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(self.file_path, "ba+", buffering=0) as f:
            f.seek(0)
            data = f.read()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            f.seek(0)
            f.write(encrypted_data)

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.current_directory = None

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add visualization type selector
        self.visualization_type = QComboBox(self)
        self.visualization_type.addItem("Matplotlib Treemap")
        self.visualization_type.addItem("Plotly Treemap")
        self.visualization_type.currentIndexChanged.connect(self.update_visualization)
        menubar.setCornerWidget(self.visualization_type, Qt.TopLeftCorner)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        # Add load data button
        self.load_button = QPushButton('Load Data', self)
        self.load_button.clicked.connect(self.load_data)
        self.load_button.setGeometry(10, 50, 100, 30)

        # Add matplotlib canvas
        self.canvas = FigureCanvas(plt.figure())
        self.setCentralWidget(self.canvas)

        # Add secure deletion options
        self.deletion_method = QComboBox(self)
        self.deletion_method.addItem("Zero Fill")
        self.deletion_method.addItem("Random Fill")
        self.deletion_method.addItem("DoD 5220.22-M")
        self.deletion_method.addItem("AES Wipe")
        self.deletion_method.setGeometry(10, 90, 150, 30)

        self.passes_label = QLabel("Passes:", self)
        self.passes_label.setGeometry(170, 90, 50, 30)

        self.passes_spinbox = QSpinBox(self)
        self.passes_spinbox.setRange(1, 10)
        self.passes_spinbox.setValue(3)
        self.passes_spinbox.setGeometry(220, 90, 50, 30)

        self.delete_button = QPushButton('Secure Delete', self)
        self.delete_button.clicked.connect(self.secure_delete)
        self.delete_button.setGeometry(10, 130, 150, 30)
    def load_data(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.current_directory = directory
            self.update_visualization()

    def update_visualization(self):
        if not self.current_directory:
            return

        files = []
        sizes = []
        for root, dirs, files in os.walk(self.current_directory):
            for file in files:
                file_path = os.path.join(root, file)
                sizes.append(os.path.getsize(file_path))
                files.append(file_path)

        data = pd.DataFrame({'File': files, 'Size': sizes})

        vis_type = self.visualization_type.currentText()
        if vis_type == "Matplotlib Treemap":
            self.plot_matplotlib_treemap(data)
        elif vis_type == "Plotly Treemap":
            self.plot_plotly_treemap(data)

    def plot_matplotlib_treemap(self, data):
        plt.clf()
        sizes = data['Size']
        labels = data['File']
        squarify.plot(sizes=sizes, label=labels, alpha=.8)
        plt.axis('off')
        self.canvas.draw()

    def plot_plotly_treemap(self, data):
        fig = px.treemap(data, path=['File'], values='Size')
        fig.show()

    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

    def open_user_manual(self):
        manual_path = os.path.join(os.path.dirname(__file__), 'user_manual.md')
        if os.path.exists(manual_path):
            with open(manual_path, 'r') as file:
                content = file.read()
                self.text_edit.setPlainText(content)
        else:
            QMessageBox.warning(self, "Error", "User manual not found.")

    def secure_delete(self):
        if not self.current_directory:
            QMessageBox.warning(self, "Error", "No directory selected.")
            return

        selected_method = self.deletion_method.currentText().lower().replace(" ", "_")
        passes = self.passes_spinbox.value()

        # For demonstration, we'll just delete the first file in the directory
        for root, dirs, files in os.walk(self.current_directory):
            if files:
                file_path = os.path.join(root, files[0])
                self.start_secure_delete(file_path, selected_method, passes)
                break

    def start_secure_delete(self, file_path, method, passes):
        self.secure_delete_thread = SecureDeleteThread(file_path, method, passes)
        self.secure_delete_thread.start()
import os
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import squarify
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QComboBox, QVBoxLayout, QWidget, QPushButton, QFileDialog
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas


class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.current_directory = None

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add visualization type selector
        self.visualization_type = QComboBox(self)
        self.visualization_type.addItem("Matplotlib Treemap")
        self.visualization_type.addItem("Plotly Treemap")
        self.visualization_type.currentIndexChanged.connect(self.update_visualization)
        menubar.setCornerWidget(self.visualization_type, Qt.TopLeftCorner)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        # Add load data button
        self.load_button = QPushButton('Load Data', self)
        self.load_button.clicked.connect(self.load_data)
        self.load_button.setGeometry(10, 50, 100, 30)

        # Add matplotlib canvas
        self.canvas = FigureCanvas(plt.figure())
        self.setCentralWidget(self.canvas)
import os
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import squarify
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QComboBox, QVBoxLayout, QWidget, QPushButton, QFileDialog
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.current_directory = None

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import QDir, Qt
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add visualization type selector
        self.visualization_type = QComboBox(self)
        self.visualization_type.addItem("Matplotlib Treemap")
        self.visualization_type.addItem("Plotly Treemap")
        self.visualization_type.currentIndexChanged.connect(self.update_visualization)
        menubar.setCornerWidget(self.visualization_type, Qt.TopLeftCorner)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        # Add load data button
        self.load_button = QPushButton('Load Data', self)
        self.load_button.clicked.connect(self.load_data)
        self.load_button.setGeometry(10, 50, 100, 30)

        # Add matplotlib canvas
        self.canvas = FigureCanvas(plt.figure())
        self.setCentralWidget(self.canvas)
    def load_data(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.current_directory = directory
            self.update_visualization()

    def update_visualization(self):
        if not self.current_directory:
            return

        files = []
        sizes = []
        for root, dirs, files in os.walk(self.current_directory):
            for file in files:
                file_path = os.path.join(root, file)
                sizes.append(os.path.getsize(file_path))
                files.append(file_path)

        data = pd.DataFrame({'File': files, 'Size': sizes})

        vis_type = self.visualization_type.currentText()
        if vis_type == "Matplotlib Treemap":
            self.plot_matplotlib_treemap(data)
        elif vis_type == "Plotly Treemap":
            self.plot_plotly_treemap(data)

    def plot_matplotlib_treemap(self, data):
        plt.clf()
        sizes = data['Size']
        labels = data['File']
        squarify.plot(sizes=sizes, label=labels, alpha=.8)
        plt.axis('off')
        self.canvas.draw()

    def plot_plotly_treemap(self, data):
        fig = px.treemap(data, path=['File'], values='Size')
        fig.show()
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt, QDir

class ShortcutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize Shortcuts")
        self.layout = QVBoxLayout(self)

        self.shortcut_labels = {}
        self.shortcut_inputs = {}

        self.add_shortcut_input("Delete File", "Ctrl+D")
        self.add_shortcut_input("Secure Delete File", "Ctrl+S")
        self.add_shortcut_input("Open Search Bar", "Ctrl+F")

        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_shortcuts)
        self.layout.addWidget(self.save_button)

    def add_shortcut_input(self, action_name, default_shortcut):
        label = QLabel(action_name, self)
        input_field = QLineEdit(default_shortcut, self)
        self.layout.addWidget(label)
        self.layout.addWidget(input_field)
        self.shortcut_labels[action_name] = label
        self.shortcut_inputs[action_name] = input_field

    def save_shortcuts(self):
        self.accept()

    def get_shortcuts(self):
        return {action: input_field.text() for action, input_field in self.shortcut_inputs.items()}

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import QDir, Qt
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shortcuts = {
            "Delete File": "Ctrl+D",
            "Secure Delete File": "Ctrl+S",
            "Open Search Bar": "Ctrl+F"
        }
        self.update_shortcuts()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add shortcut customization
        settings_menu = menubar.addMenu('Settings')
        customize_shortcuts_action = QAction('Customize Shortcuts', self)
        customize_shortcuts_action.triggered.connect(self.open_shortcut_dialog)
        settings_menu.addAction(customize_shortcuts_action)
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shortcuts = {
            "Delete File": "Ctrl+D",
            "Secure Delete File": "Ctrl+S",
            "Open Search Bar": "Ctrl+F"
        }
        self.update_shortcuts()
    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add shortcut customization
        settings_menu = menubar.addMenu('Settings')
        customize_shortcuts_action = QAction('Customize Shortcuts', self)
        customize_shortcuts_action.triggered.connect(self.open_shortcut_dialog)
        settings_menu.addAction(customize_shortcuts_action)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)
    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

    def load_data(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.current_directory = directory
            self.update_visualization()

    def update_visualization(self):
        if not self.current_directory:
            return

        files = []
        sizes = []
        for root, dirs, files in os.walk(self.current_directory):
            for file in files:
                file_path = os.path.join(root, file)
                sizes.append(os.path.getsize(file_path))
                files.append(file_path)

        data = pd.DataFrame({'File': files, 'Size': sizes})

        vis_type = self.visualization_type.currentText()
        if vis_type == "Matplotlib Treemap":
            self.plot_matplotlib_treemap(data)
        elif vis_type == "Plotly Treemap":
            self.plot_plotly_treemap(data)

    def plot_matplotlib_treemap(self, data):
        plt.clf()
        sizes = data['Size']
        labels = data['File']
        squarify.plot(sizes=sizes, label=labels, alpha=.8)
        plt.axis('off')
        self.canvas.draw()

    def plot_plotly_treemap(self, data):
        fig = px.treemap(data, path=['File'], values='Size')
        fig.show()

    def open_shortcut_dialog(self):
        dialog = ShortcutDialog(self)
        if dialog.exec_():
            self.shortcuts = dialog.get_shortcuts()
            self.update_shortcuts()

    def update_shortcuts(self):
        self.shortcut_actions = {
            "Delete File": QAction(self),
            "Secure Delete File": QAction(self),
            "Open Search Bar": QAction(self)
        }
        for action_name, shortcut in self.shortcuts.items():
            self.shortcut_actions[action_name].setShortcut(shortcut)
            self.shortcut_actions[action_name].triggered.connect(getattr(self, action_name.replace(" ", "_").lower()))
            self.addAction(self.shortcut_actions[action_name])

    def delete_file(self):
        print("Delete File action triggered")

    def secure_delete_file(self):
        print("Secure Delete File action triggered")

    def open_search_bar(self):
        print("Open Search Bar action triggered")
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt, QDir

class ShortcutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize Shortcuts")
        self.layout = QVBoxLayout(self)

        self.shortcut_labels = {}
        self.shortcut_inputs = {}

        self.add_shortcut_input("Delete File", "Ctrl+D")
        self.add_shortcut_input("Secure Delete File", "Ctrl+S")
        self.add_shortcut_input("Open Search Bar", "Ctrl+F")

        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_shortcuts)
        self.layout.addWidget(self.save_button)

    def add_shortcut_input(self, action_name, default_shortcut):
        label = QLabel(action_name, self)
        input_field = QLineEdit(default_shortcut, self)
        self.layout.addWidget(label)
        self.layout.addWidget(input_field)
        self.shortcut_labels[action_name] = label
        self.shortcut_inputs[action_name] = input_field

    def save_shortcuts(self):
        self.accept()

    def get_shortcuts(self):
        return {action: input_field.text() for action, input_field in self.shortcut_inputs.items()}

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import QDir, Qt
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shortcuts = {
            "Delete File": "Ctrl+D",
            "Secure Delete File": "Ctrl+S",
            "Open Search Bar": "Ctrl+F"
        }
        self.update_shortcuts()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add shortcut customization
        settings_menu = menubar.addMenu('Settings')
        customize_shortcuts_action = QAction('Customize Shortcuts', self)
        customize_shortcuts_action.triggered.connect(self.open_shortcut_dialog)
        settings_menu.addAction(customize_shortcuts_action)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

    def open_user_manual(self):
        manual_path = os.path.join(os.path.dirname(__file__), 'user_manual.md')
        if os.path.exists(manual_path):
            with open(manual_path, 'r') as file:
                content = file.read()
                self.text_edit.setPlainText(content)
        else:
            QMessageBox.warning(self, "Error", "User manual not found.")

    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

    def open_shortcut_dialog(self):
        dialog = ShortcutDialog(self)
        if dialog.exec_():
            self.shortcuts = dialog.get_shortcuts()
            self.update_shortcuts()

    def update_shortcuts(self):
        self.shortcut_actions = {
            "Delete File": QAction(self),
            "Secure Delete File": QAction(self),
            "Open Search Bar": QAction(self)
        }
        for action_name, shortcut in self.shortcuts.items():
            self.shortcut_actions[action_name].setShortcut(shortcut)
            self.shortcut_actions[action_name].triggered.connect(getattr(self, action_name.replace(" ", "_").lower()))
            self.addAction(self.shortcut_actions[action_name])

    def delete_file(self):
        print("Delete File action triggered")

    def secure_delete_file(self):
        print("Secure Delete File action triggered")

    def open_search_bar(self):
        print("Open Search Bar action triggered")
    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

if __name__ == '__main__':
    app = QApplication([])
    window = ShredSpaceApp()
    window.show()
    app.exec_()
import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureDeleteThread(QThread):
    def __init__(self, file_path, method, passes):
        super().__init__()
        self.file_path = file_path
        self.method = method
        self.passes = passes

    def run(self):
        if self.method == 'zero':
            self.zero_fill()
        elif self.method == 'random':
            self.random_fill()
        elif self.method == 'dod':
            self.dod_standard()
        elif self.method == 'aes':
            self.aes_wipe()
        os.remove(self.file_path)

    def zero_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(b'\x00' * os.path.getsize(self.file_path))

    def random_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def dod_standard(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(3):  # DoD 5220.22-M standard is 3 passes
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def aes_wipe(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(self.file_path, "ba+", buffering=0) as f:
            f.seek(0)
            data = f.read()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            f.seek(0)
            f.write(encrypted_data)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt, QDir

class ShortcutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize Shortcuts")
        self.layout = QVBoxLayout(self)

        self.shortcut_labels = {}
        self.shortcut_inputs = {}

        self.add_shortcut_input("Delete File", "Ctrl+D")
        self.add_shortcut_input("Secure Delete File", "Ctrl+S")
        self.add_shortcut_input("Open Search Bar", "Ctrl+F")

        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_shortcuts)
        self.layout.addWidget(self.save_button)

    def add_shortcut_input(self, action_name, default_shortcut):
        label = QLabel(action_name, self)
        input_field = QLineEdit(default_shortcut, self)
        self.layout.addWidget(label)
        self.layout.addWidget(input_field)
        self.shortcut_labels[action_name] = label
        self.shortcut_inputs[action_name] = input_field

    def save_shortcuts(self):
        self.accept()

    def get_shortcuts(self):
        return {action: input_field.text() for action, input_field in self.shortcut_inputs.items()}

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import squarify
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QComboBox, QVBoxLayout, QWidget, QPushButton, QFileDialog
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.current_directory = None

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import QDir, Qt
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add visualization type selector
        self.visualization_type = QComboBox(self)
        self.visualization_type.addItem("Matplotlib Treemap")
        self.visualization_type.addItem("Plotly Treemap")
        self.visualization_type.currentIndexChanged.connect(self.update_visualization)
        menubar.setCornerWidget(self.visualization_type, Qt.TopLeftCorner)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        # Add load data button
        self.load_button = QPushButton('Load Data', self)
        self.load_button.clicked.connect(self.load_data)
        self.load_button.setGeometry(10, 50, 100, 30)

        # Add matplotlib canvas
        self.canvas = FigureCanvas(plt.figure())
        self.setCentralWidget(self.canvas)
    def load_data(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.current_directory = directory
            self.update_visualization()

    def update_visualization(self):
        if not self.current_directory:
            return

        files = []
        sizes = []
        for root, dirs, files in os.walk(self.current_directory):
            for file in files:
                file_path = os.path.join(root, file)
                sizes.append(os.path.getsize(file_path))
                files.append(file_path)

        data = pd.DataFrame({'File': files, 'Size': sizes})

        vis_type = self.visualization_type.currentText()
        if vis_type == "Matplotlib Treemap":
            self.plot_matplotlib_treemap(data)
        elif vis_type == "Plotly Treemap":
            self.plot_plotly_treemap(data)

    def plot_matplotlib_treemap(self, data):
        plt.clf()
        sizes = data['Size']
        labels = data['File']
        squarify.plot(sizes=sizes, label=labels, alpha=.8)
        plt.axis('off')
        self.canvas.draw()

    def plot_plotly_treemap(self, data):
        fig = px.treemap(data, path=['File'], values='Size')
        fig.show()
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt, QDir

class ShortcutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize Shortcuts")
        self.layout = QVBoxLayout(self)

        self.shortcut_labels = {}
        self.shortcut_inputs = {}

        self.add_shortcut_input("Delete File", "Ctrl+D")
        self.add_shortcut_input("Secure Delete File", "Ctrl+S")
        self.add_shortcut_input("Open Search Bar", "Ctrl+F")

        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_shortcuts)
        self.layout.addWidget(self.save_button)

    def add_shortcut_input(self, action_name, default_shortcut):
        label = QLabel(action_name, self)
        input_field = QLineEdit(default_shortcut, self)
        self.layout.addWidget(label)
        self.layout.addWidget(input_field)
        self.shortcut_labels[action_name] = label
        self.shortcut_inputs[action_name] = input_field

    def save_shortcuts(self):
        self.accept()

    def get_shortcuts(self):
        return {action: input_field.text() for action, input_field in self.shortcut_inputs.items()}

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import QDir, Qt
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shortcuts = {
            "Delete File": "Ctrl+D",
            "Secure Delete File": "Ctrl+S",
            "Open Search Bar": "Ctrl+F"
        }
        self.update_shortcuts()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add shortcut customization
        settings_menu = menubar.addMenu('Settings')
        customize_shortcuts_action = QAction('Customize Shortcuts', self)
        customize_shortcuts_action.triggered.connect(self.open_shortcut_dialog)
        settings_menu.addAction(customize_shortcuts_action)
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shortcuts = {
            "Delete File": "Ctrl+D",
            "Secure Delete File": "Ctrl+S",
            "Open Search Bar": "Ctrl+F"
        }
        self.update_shortcuts()
    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add shortcut customization
        settings_menu = menubar.addMenu('Settings')
        customize_shortcuts_action = QAction('Customize Shortcuts', self)
        customize_shortcuts_action.triggered.connect(self.open_shortcut_dialog)
        settings_menu.addAction(customize_shortcuts_action)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)
    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

    def open_shortcut_dialog(self):
        dialog = ShortcutDialog(self)
        if dialog.exec_():
            self.shortcuts = dialog.get_shortcuts()
            self.update_shortcuts()

    def update_shortcuts(self):
        self.shortcut_actions = {
            "Delete File": QAction(self),
            "Secure Delete File": QAction(self),
            "Open Search Bar": QAction(self)
        }
        for action_name, shortcut in self.shortcuts.items():
            self.shortcut_actions[action_name].setShortcut(shortcut)
            self.shortcut_actions[action_name].triggered.connect(getattr(self, action_name.replace(" ", "_").lower()))
            self.addAction(self.shortcut_actions[action_name])

    def delete_file(self):
        print("Delete File action triggered")

    def secure_delete_file(self):
        print("Secure Delete File action triggered")

    def open_search_bar(self):
        print("Open Search Bar action triggered")
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import Qt, QDir

class ShortcutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize Shortcuts")
        self.layout = QVBoxLayout(self)

        self.shortcut_labels = {}
        self.shortcut_inputs = {}

        self.add_shortcut_input("Delete File", "Ctrl+D")
        self.add_shortcut_input("Secure Delete File", "Ctrl+S")
        self.add_shortcut_input("Open Search Bar", "Ctrl+F")

        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_shortcuts)
        self.layout.addWidget(self.save_button)

    def add_shortcut_input(self, action_name, default_shortcut):
        label = QLabel(action_name, self)
        input_field = QLineEdit(default_shortcut, self)
        self.layout.addWidget(label)
        self.layout.addWidget(input_field)
        self.shortcut_labels[action_name] = label
        self.shortcut_inputs[action_name] = input_field

    def save_shortcuts(self):
        self.accept()

    def get_shortcuts(self):
        return {action: input_field.text() for action, input_field in self.shortcut_inputs.items()}

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QTextEdit, QMessageBox, QMenu, QComboBox
from PyQt5.QtGui import QIcon, QFontDatabase, QFont
from PyQt5.QtCore import QDir, Qt
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)
class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shortcuts = {
            "Delete File": "Ctrl+D",
            "Secure Delete File": "Ctrl+S",
            "Open Search Bar": "Ctrl+F"
        }
        self.update_shortcuts()

    def initUI(self):
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)

        # Load FontAwesome
        font_id = QFontDatabase.addApplicationFont("icons/fontawesome/fontawesome-webfont.ttf")
        if font_id == -1:
            print("Failed to load FontAwesome font.")
        else:
            fontawesome = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.fa_font = QFont(fontawesome)

        # Create menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu('Help')

        # Add 'User Manual' action with system icon
        user_manual_action = QAction(QIcon.fromTheme('help-contents'), 'User Manual', self)
        user_manual_action.triggered.connect(self.open_user_manual)
        help_menu.addAction(user_manual_action)

        # Add 'More Info' action with FontAwesome icon
        fa_icon = chr(0xf05a)  # FontAwesome unicode for 'info-circle'
        fa_action = QAction(fa_icon + ' More Info', self)
        fa_action.setFont(self.fa_font)
        help_menu.addAction(fa_action)

        # Add Dark Mode toggle
        view_menu = menubar.addMenu('View')
        dark_mode_action = QAction('Toggle Dark Mode', self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_mode_action)

        # Add file type filter
        self.file_type_filter = QComboBox(self)
        self.file_type_filter.addItem("All Files")
        self.file_type_filter.addItem("Images")
        self.file_type_filter.addItem("Documents")
        self.file_type_filter.currentIndexChanged.connect(self.filter_files)
        menubar.setCornerWidget(self.file_type_filter, Qt.TopRightCorner)

        # Add shortcut customization
        settings_menu = menubar.addMenu('Settings')
        customize_shortcuts_action = QAction('Customize Shortcuts', self)
        customize_shortcuts_action.triggered.connect(self.open_shortcut_dialog)
        settings_menu.addAction(customize_shortcuts_action)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

    def open_user_manual(self):
        manual_path = os.path.join(os.path.dirname(__file__), 'user_manual.md')
        if os.path.exists(manual_path):
            with open(manual_path, 'r') as file:
                content = file.read()
                self.text_edit.setPlainText(content)
        else:
            QMessageBox.warning(self, "Error", "User manual not found.")

    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

    def open_shortcut_dialog(self):
        dialog = ShortcutDialog(self)
        if dialog.exec_():
            self.shortcuts = dialog.get_shortcuts()
            self.update_shortcuts()

    def update_shortcuts(self):
        self.shortcut_actions = {
            "Delete File": QAction(self),
            "Secure Delete File": QAction(self),
            "Open Search Bar": QAction(self)
        }
        for action_name, shortcut in self.shortcuts.items():
            self.shortcut_actions[action_name].setShortcut(shortcut)
            self.shortcut_actions[action_name].triggered.connect(getattr(self, action_name.replace(" ", "_").lower()))
            self.addAction(self.shortcut_actions[action_name])

    def delete_file(self):
        print("Delete File action triggered")

    def secure_delete_file(self):
        print("Secure Delete File action triggered")

    def open_search_bar(self):
        print("Open Search Bar action triggered")
    def toggle_dark_mode(self):
        if self.styleSheet():
            self.setStyleSheet("")
        else:
            with open("dark_mode.qss", "r") as file:
                self.setStyleSheet(file.read())

    def filter_files(self):
        filter_text = self.file_type_filter.currentText()
        # Implement file filtering logic here
        if filter_text == "All Files":
            # Show all files
            pass
        elif filter_text == "Images":
            # Show only image files
            pass
        elif filter_text == "Documents":
            # Show only document files
            pass

if __name__ == '__main__':
    app = QApplication([])
    window = ShredSpaceApp()
    window.show()
    app.exec_()
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import squarify
import plotly.express as px
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, 
                             QFileDialog, QProgressBar, QLabel, QLineEdit, QMessageBox, QMenuBar, QMenu, QAction, QComboBox, QSlider, QListWidget)
class PaginatedListWidget(QWidget):
    def __init__(self, items, items_per_page=100, parent=None):
        super().__init__(parent)
        self.list_widget = QListWidget(self)
        self.next_button = QPushButton("Next", self)
        self.prev_button = QPushButton("Previous", self)
        self.items = items
        self.items_per_page = items_per_page
        self.current_page = 0

        layout = QVBoxLayout(self)
        layout.addWidget(self.list_widget)
        layout.addWidget(self.prev_button)
        layout.addWidget(self.next_button)

        self.prev_button.clicked.connect(self.previous_page)
        self.next_button.clicked.connect(self.next_page)

        self.update_display()

    def update_display(self):
        self.list_widget.clear()
        start_index = self.current_page * self.items_per_page
        end_index = start_index + self.items_per_page
        for item in self.items[start_index:end_index]:
            self.list_widget.addItem(item)

        self.prev_button.setEnabled(self.current_page > 0)
        self.next_button.setEnabled(end_index < len(self.items))

    def next_page(self):
        self.current_page += 1
        self.update_display()

    def previous_page(self):
        self.current_page -= 1
        self.update_display()
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import squarify
import plotly.express as px
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, 
                             QFileDialog, QProgressBar, QLabel, QLineEdit, QMessageBox, QMenuBar, QMenu, QAction, QComboBox, QSlider, QListWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import shutil
import numpy as np
import json
import matplotlib.patches as patches
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import cProfile
import pstats

# Define theme colors globally
theme_colors = {
    "Rainbow": ['#FFB554', '#FFA054', '#FF8054', '#FF5454', '#E64C8D', '#D145C1', '#8C3FC0', '#5240C3', '#4262C7', '#438CCB', '#46ACD3', '#45D2B0', '#4DC742', '#8CD466', '#C8E64C', '#FFFF54'],
    "Green Eggs": ['#58A866', '#AAE009', '#9EFC7D', '#FFF07A', '#FBBF51', '#FFFF00', '#009ACD', '#FF2626', '#E85AAA', '#D1C57E', '#CE95C8', '#5ABFC6'],
    "Olive Sunset": ['#990033', '#CC0033', '#FF9966', '#FFFFCC', '#CCCC99', '#CCCC33', '#999900', '#666600', '#003366', '#006699', '#3399CC', '#99CCCC'],
    "Lagoon Nebula": ['#325086', '#9ED5AE', '#D86562', '#845D4E', '#F4AD6F', '#98C8D6', '#5A272C', '#CFAD4B'],
    "Monaco": ['#EC8921', '#DB4621', '#D92130', '#38B236', '#3DBFCC', '#2A91D2', '#7378D4']
}

class FileScannerThread(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(pd.DataFrame)

    def __init__(self, directory):
        super().__init__()
        self.directory = directory

    def run(self):
        file_sizes = []
        file_names = []
        total_files = len([f for f in os.listdir(self.directory) if not f.startswith('.')])
        increment = 100 / total_files if total_files > 0 else 1

        for index, filename in enumerate(os.listdir(self.directory)):
            if filename.startswith('.'):
                continue  # Skip hidden files
            path = os.path.join(self.directory, filename)
            if os.path.isfile(path):
                file_sizes.append(os.stat(path).st_size)
                file_names.append(filename)
            self.progress.emit(int((index + 1) * increment))

        data = {'name': file_names, 'size': file_sizes}
        df = pd.DataFrame(data)
        self.result.emit(df)

class SecureDeleteThread(QThread):
    def __init__(self, file_path, method, passes):
        super().__init__()
        self.file_path = file_path
        self.method = method
        self.passes = passes

    def run(self):
        if self.method == 'zero':
            self.zero_fill()
        elif self.method == 'random':
            self.random_fill()
        elif self.method == 'dod':
            self.dod_standard()
        elif self.method == 'aes':
            self.aes_wipe()
        os.remove(self.file_path)

    def zero_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(b'\x00' * os.path.getsize(self.file_path))

    def random_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def dod_standard(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(3):  # DoD 5220.22-M standard is 3 passes
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def aes_wipe(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(self.file_path, "ba+", buffering=0) as f:
            f.seek(0)
            data = f.read()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            f.seek(0)
            f.write(encrypted_data)

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)
        self.current_directory = None
        self.selected_file = None
        self.settings = self.load_settings()
        self.initUI()

    def compile_user_manual(self):
        manual_directory = 'manuals'  # Directory containing markdown files
        output_file_path = os.path.join(manual_directory, 'user_manual.md')  # Path to save the compiled manual

        # Ensure the directory exists
        if not os.path.exists(manual_directory):
            os.makedirs(manual_directory)
            QMessageBox.information(self, "Directory Missing", "The manuals directory does not exist and was created. Please add markdown files.")
            return

        # Read all markdown files and compile them into one
        manual_files = [f for f in os.listdir(manual_directory) if f.endswith('.md')]
        if not manual_files:
            QMessageBox.information(self, "No Files Found", "No markdown files found in the manuals directory.")
            return

        with open(output_file_path, 'w') as outfile:
            for fname in manual_files:
                with open(os.path.join(manual_directory, fname), 'r') as infile:
                    outfile.write(infile.read() + '\n\n')

        QMessageBox.information(self, "User Manual Compiled", f"User manual has been compiled and saved as '{output_file_path}'.")
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)
        self.current_directory = None
        self.selected_file = None
        self.settings = self.load_settings()
        self.initUI()

    def compile_user_manual(self):
        manual_directory = 'manuals'  # Directory containing markdown files
        output_file_path = os.path.join(manual_directory, 'user_manual.md')  # Path to save the compiled manual

        # Ensure the directory exists
        if not os.path.exists(manual_directory):
            os.makedirs(manual_directory)
            QMessageBox.information(self, "Directory Missing", "The manuals directory does not exist and was created. Please add markdown files.")
            return

        # Read all markdown files and compile them into one
        manual_files = [f for f in os.listdir(manual_directory) if f.endswith('.md')]
        if not manual_files:
            QMessageBox.information(self, "No Files Found", "No markdown files found in the manuals directory.")
            return

        with open(output_file_path, 'w') as outfile:
            for fname in manual_files:
                with open(os.path.join(manual_directory, fname), 'r') as infile:
                    outfile.write(infile.read() + '\n\n')

        QMessageBox.information(self, "User Manual Compiled", f"User manual has been compiled and saved as '{output_file_path}'.")

    def initUI(self):
        main_layout = QVBoxLayout()
        toolbar_layout = QHBoxLayout()

        self.load_button = QPushButton('Load Data')
        self.load_button.clicked.connect(self.load_data)
        toolbar_layout.addWidget(self.load_button)

        self.search_var = QLineEdit()
        self.search_var.textChanged.connect(self.update_search_results)
        toolbar_layout.addWidget(self.search_var)

        self.search_button = QPushButton('Search')
        self.search_button.clicked.connect(self.search_files)
        toolbar_layout.addWidget(self.search_button)

        self.delete_button = QPushButton('Delete')
        self.delete_button.clicked.connect(self.delete_file)
        self.delete_button.setEnabled(False)
        toolbar_layout.addWidget(self.delete_button)

        self.secure_delete_button = QPushButton('Secure Delete')
        self.secure_delete_button.clicked.connect(self.secure_delete_file)
        self.secure_delete_button.setEnabled(False)
        toolbar_layout.addWidget(self.secure_delete_button)

        self.progress_bar = QProgressBar()
        toolbar_layout.addWidget(self.progress_bar)

        self.passes_slider = QSlider(Qt.Horizontal, self)
        self.passes_slider.setMinimum(1)
        self.passes_slider.setMaximum(99)
        self.passes_slider.setValue(3)
        self.passes_slider.valueChanged.connect(self.update_passes)
        toolbar_layout.addWidget(self.passes_slider)

        main_layout.addLayout(toolbar_layout)

        self.canvas = FigureCanvas(plt.figure(figsize=(10, 8)))
        main_layout.addWidget(self.canvas)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.create_menu()

        self.toolbar = self.addToolBar('Main Toolbar')
        delete_action = QAction(QIcon('delete.png'), 'Delete', self)
        secure_delete_action = QAction(QIcon('secure_delete.png'), 'Secure Delete', self)
        self.toolbar.addAction(delete_action)
        self.toolbar.addAction(secure_delete_action)
        delete_action.triggered.connect(self.delete_file)
        secure_delete_action.triggered.connect(self.secure_delete_file)

        self.search_bar = QLineEdit(self)
        self.search_bar.textChanged.connect(self.update_search_results)
        self.setCentralWidget(self.search_bar)

        # Assuming you have a QListWidget or similar to display results
        self.paginated_list = PaginatedListWidget([], parent=self)
        self.setCentralWidget(self.paginated_list)
        main_layout = QVBoxLayout()
        toolbar_layout = QHBoxLayout()

        self.load_button = QPushButton('Load Data')
        self.load_button.clicked.connect(self.load_data)
        toolbar_layout.addWidget(self.load_button)

        self.search_var = QLineEdit()
        self.search_var.textChanged.connect(self.update_search_results)
        toolbar_layout.addWidget(self.search_var)

        self.search_button = QPushButton('Search')
        self.search_button.clicked.connect(self.search_files)
        toolbar_layout.addWidget(self.search_button)

        self.delete_button = QPushButton('Delete')
        self.delete_button.clicked.connect(self.delete_file)
        self.delete_button.setEnabled(False)
        toolbar_layout.addWidget(self.delete_button)

        self.secure_delete_button = QPushButton('Secure Delete')
        self.secure_delete_button.clicked.connect(self.secure_delete_file)
        self.secure_delete_button.setEnabled(False)
        toolbar_layout.addWidget(self.secure_delete_button)

        self.progress_bar = QProgressBar()
        toolbar_layout.addWidget(self.progress_bar)

        self.passes_slider = QSlider(Qt.Horizontal, self)
        self.passes_slider.setMinimum(1)
        self.passes_slider.setMaximum(99)
        self.passes_slider.setValue(3)
        self.passes_slider.valueChanged.connect(self.update_passes)
        toolbar_layout.addWidget(self.passes_slider)

        main_layout.addLayout(toolbar_layout)

        self.canvas = FigureCanvas(plt.figure(figsize=(10, 8)))
        main_layout.addWidget(self.canvas)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.create_menu()

        self.toolbar = self.addToolBar('Main Toolbar')
        delete_action = QAction(QIcon('delete.png'), 'Delete', self)
        secure_delete_action = QAction(QIcon('secure_delete.png'), 'Secure Delete', self)
        self.toolbar.addAction(delete_action)
        self.toolbar.addAction(secure_delete_action)
        delete_action.triggered.connect(self.delete_file)
        secure_delete_action.triggered.connect(self.secure_delete_file)

        self.search_bar = QLineEdit(self)
        self.search_bar.textChanged.connect(self.update_search_results)
        self.setCentralWidget(self.search_bar)

        # Assuming you have a QListWidget or similar to display results
        self.paginated_list = PaginatedListWidget([], parent=self)
        self.setCentralWidget(self.paginated_list)

    def create_menu(self):
        menubar = self.menuBar()
        settings_menu = menubar.addMenu('Settings')

        color_theme_menu = QMenu('Color Theme', self)
        settings_menu.addMenu(color_theme_menu)
    
        # Monaco as a default and disabled item
        default_action = QAction('Monaco (Default)', self)
        default_action.setEnabled(False)
        color_theme_menu.addAction(default_action)

        for theme in theme_colors.keys():
            if theme != 'Monaco':
                action = QAction(theme, self)
                action.triggered.connect(lambda checked, theme=theme: self.set_color_theme(theme))
                color_theme_menu.addAction(action)

        settings_menu.addSeparator()

        sort_menu = QMenu('Sort Options', self)
        settings_menu.addMenu(sort_menu)

        # Adding more sort actions
        sort_by_name_action = QAction('Sort by Name', self)
        sort_by_size_action = QAction('Sort by Size', self)
        sort_by_type_action = QAction('Sort by Type', self)
        sort_by_date_action = QAction('Sort by Date Modified', self)

        sort_menu.addAction(sort_by_name_action)
        sort_menu.addAction(sort_by_size_action)
        sort_menu.addAction(sort_by_type_action)
        sort_menu.addAction(sort_by_date_action)

        # Connect these actions to their respective functions
        sort_by_name_action.triggered.connect(lambda: self.apply_sort('name'))
        sort_by_size_action.triggered.connect(lambda: self.apply_sort('size'))
        sort_by_type_action.triggered.connect(lambda: self.apply_sort('type'))
        sort_by_date_action.triggered.connect(lambda: self.apply_sort('date'))

        recent_scans_menu = QMenu('Recent Scans', self)
        settings_menu.addMenu(recent_scans_menu)

        self.recent_scans_actions = []
        for directory in self.settings.get('recent_scans', []):
            action = QAction(directory, self)
            action.triggered.connect(lambda checked, dir=directory: self.load_recent_scan(dir))
            recent_scans_menu.addAction(action)
            self.recent_scans_actions.append(action)

    def load_settings(self):
        try:
            with open('settings.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {'color_theme': 'Monaco', 'recent_scans': []}

    def save_settings(self):
        with open('settings.json', 'w') as f:
            json.dump(self.settings, f)

    def set_color_theme(self, theme):
        self.settings['color_theme'] = theme
        self.save_settings()
        if self.current_directory:
            self.load_data()

    def load_recent_scan(self, directory):
        self.current_directory = directory
        self.load_data()

    def load_data(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")

        if directory:
            self.current_directory = directory
            if directory not in self.settings['recent_scans']:
                self.settings['recent_scans'].insert(0, directory)
                if len(self.settings['recent_scans']) > 30:
                    self.settings['recent_scans'].pop()
                self.save_settings()
            self.scan_directory()

    def scan_directory(self):
        self.progress_bar.setValue(0)
        self.file_scanner_thread = FileScannerThread(self.current_directory)
        self.file_scanner_thread.progress.connect(self.progress_bar.setValue)
        self.file_scanner_thread.result.connect(self.display_data)
        self.file_scanner_thread.start()

    def display_data(self, df):
        self.create_interactive_treemap(df, self.settings['color_theme'])

    def create_interactive_treemap(self, data, color_scheme):
        plt.clf()
        labels = [f"{name}\n{size} bytes" for name, size in zip(data['name'], data['size'])]
        sizes = data['size']
        colors = [theme_colors[self.settings['color_theme']][int(i % len(theme_colors[self.settings['color_theme']]))] for i in range(len(data))]

        fig, ax = plt.subplots()
        squarify.plot(sizes=sizes, label=labels, color=colors, alpha=0.6, ax=ax, pad=False)
        plt.axis('off')

        # Apply gradient effect
        for rect in ax.patches:
            x, y, dx, dy = rect.get_x(), rect.get_y(), rect.get_width(), rect.get_height()
            gradient_patch = patches.Rectangle((x, y), dx, dy, color='white', alpha=0.3)
            ax.add_patch(gradient_patch)

        self.canvas.figure = fig
        self.canvas.draw()

        # Connect the click event
        self.canvas.mpl_connect('button_press_event', self.on_click)

    def apply_sort(self, sort_by):
        if not self.current_directory:
            QMessageBox.information(self, "Error", "No directory selected.")
            return

        files = os.listdir(self.current_directory)
        if sort_by == 'name':
            sorted_files = sorted(files)
        elif sort_by == 'size':
            sorted_files = sorted(files, key=lambda x: os.path.getsize(os.path.join(self.current_directory, x)))
        elif sort_by == 'type':
            sorted_files = sorted(files, key=lambda x: os.path.splitext(x)[1])
        elif sort_by == 'date':
            sorted_files = sorted(files, key=lambda x: os.path.getmtime(os.path.join(self.current_directory, x)))

        file_details = [(f, os.path.getsize(os.path.join(self.current_directory, f))) for f in sorted_files]
        df = pd.DataFrame(file_details, columns=['name', 'size'])
        self.display_data(df)

    def on_click(self, event):
        # Get the coordinates of the click
        x, y = event.xdata, event.ydata
        if x is not None and y is not None:
            # Find the rectangle that was clicked
            for rect in self.canvas.figure.axes[0].patches:
                if rect.contains_point((x, y)):
                    label = rect.get_label()
                    file_name = label.split('\n')[0]
                    self.selected_file = file_name
                    self.delete_button.setEnabled(True)
                    self.secure_delete_button.setEnabled(True)
                    QMessageBox.information(self, "File Selected", f"Selected file: {file_name}")
                    break

    def get_selected_file(self):
        return self.selected_file if self.selected_file else None

    def delete_file(self):
        selected_file = self.get_selected_file()
        if selected_file:
            file_path = os.path.join(self.current_directory, selected_file)
            os.remove(file_path)
            QMessageBox.information(self, "Success", f"Deleted {selected_file}")
            self.delete_button.setEnabled(False)
            self.secure_delete_button.setEnabled(False)

    def secure_delete_file(self):
        selected_file = self.get_selected_file()
        if selected_file:
            file_path = os.path.join(self.current_directory, selected_file)
            method = self.settings.get('secure_delete_method', 'dod')
            passes = self.passes_slider.value()

            if not self.validate_passes(passes):
                return

            self.progress_bar.setValue(0)

            self.secure_delete_thread = SecureDeleteThread(file_path, method, passes)
            self.secure_delete_thread.progress.connect(self.progress_bar.setValue)
            self.secure_delete_thread.finished.connect(self.on_secure_delete_finished)
            self.secure_delete_thread.start()

    def on_secure_delete_finished(self):
        QMessageBox.information(self, "Success", f"Securely deleted {self.selected_file}")
        self.delete_button.setEnabled(False)
        self.secure_delete_button.setEnabled(False)

    def update_passes(self, value):
        self.settings['secure_delete_passes'] = value
        self.save_settings()

    def validate_passes(self, passes):
        if not (1 <= passes <= 99):
            QMessageBox.warning(self, "Invalid Input", "Number of passes must be between 1 and 99.")
            return False
        return True

    def update_search_results(self, text):
        if not text.strip():
            self.clear_search_results()
            return

        # Assuming `self.file_list` contains all the filenames in the current directory
        filtered_files = [filename for filename in self.file_list if text.lower() in filename.lower()]
        self.display_search_results(filtered_files)

    def display_search_results(self, filtered_files):
        self.paginated_list.items = filtered_files
        self.paginated_list.current_page = 0
        self.paginated_list.update_display()

    def clear_search_results(self):
        self.paginated_list.items = []
        self.paginated_list.current_page = 0
        self.paginated_list.update_display()
        if not text.strip():
            self.clear_search_results()
            return

        # Assuming `self.file_list` contains all the filenames in the current directory
        filtered_files = [filename for filename in self.file_list if text.lower() in filename.lower()]
        self.display_search_results(filtered_files)

    def display_search_results(self, filtered_files):
        self.paginated_list.items = filtered_files
        self.paginated_list.current_page = 0
        self.paginated_list.update_display()

    def clear_search_results(self):
        self.paginated_list.items = []
        self.paginated_list.current_page = 0
        self.paginated_list.update_display()

    def search_files(self):
        search_term = self.search_box.text().lower()
        filtered_data = self.data[self.data['name'].str.contains(search_term, case=False, na=False)]
        
        if filtered_data.empty:
            QMessageBox.information(self, "No Results", f"No files found matching: {search_term}")
        else:
            self.create_interactive_treemap(filtered_data, 'Rainbow')
        print("Search for:", search_term)
        pass

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Down:
            self.paginated_list.list_widget.setCurrentRow(
                (self.paginated_list.list_widget.currentRow() + 1) % self.paginated_list.list_widget.count()
            )
        elif event.key() == Qt.Key_Up:
            self.paginated_list.list_widget.setCurrentRow(
                (self.paginated_list.list_widget.currentRow() - 1 + self.paginated_list.list_widget.count()) % self.paginated_list.list_widget.count()
            )
        elif event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self.select_file()

    def select_file(self):
        selected_item = self.paginated_list.list_widget.currentItem()
        if selected_item:
            selected_file = selected_item.text()
            QMessageBox.information(self, "File Selected", f"Selected file: {selected_file}")
    def setup_accessibility(self):
        self.setAccessibleName("Main Window")
        self.setAccessibleDescription("This is the main window of the application with file management features.")

    def profile_application(self, function_to_profile):
        profiler = cProfile.Profile()
        profiler.enable()
        function_to_profile()
        profiler.disable()
        stats = pstats.Stats(profiler).sort_stats('cumtime')
        stats.print_stats()
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import squarify
import plotly.express as px
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, 
                             QFileDialog, QProgressBar, QLabel, QLineEdit, QMessageBox, QMenuBar, QMenu, QAction, QComboBox, QSlider, QListWidget)
class PaginatedListWidget(QWidget):
    def __init__(self, items, items_per_page=100, parent=None):
        super().__init__(parent)
        self.list_widget = QListWidget(self)
        self.next_button = QPushButton("Next", self)
        self.prev_button = QPushButton("Previous", self)
        self.items = items
        self.items_per_page = items_per_page
        self.current_page = 0

        layout = QVBoxLayout(self)
        layout.addWidget(self.list_widget)
        layout.addWidget(self.prev_button)
        layout.addWidget(self.next_button)

        self.prev_button.clicked.connect(self.previous_page)
        self.next_button.clicked.connect(self.next_page)

        self.update_display()

    def update_display(self):
        self.list_widget.clear()
        start_index = self.current_page * self.items_per_page
        end_index = start_index + self.items_per_page
        for item in self.items[start_index:end_index]:
            self.list_widget.addItem(item)

        self.prev_button.setEnabled(self.current_page > 0)
        self.next_button.setEnabled(end_index < len(self.items))

    def next_page(self):
        self.current_page += 1
        self.update_display()

    def previous_page(self):
        self.current_page -= 1
        self.update_display()
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import squarify
import plotly.express as px
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, 
                             QFileDialog, QProgressBar, QLabel, QLineEdit, QMessageBox, QMenuBar, QMenu, QAction, QComboBox, QSlider, QListWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import shutil
import numpy as np
import json
import matplotlib.patches as patches
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import cProfile
import pstats

# Define theme colors globally
theme_colors = {
    "Rainbow": ['#FFB554', '#FFA054', '#FF8054', '#FF5454', '#E64C8D', '#D145C1', '#8C3FC0', '#5240C3', '#4262C7', '#438CCB', '#46ACD3', '#45D2B0', '#4DC742', '#8CD466', '#C8E64C', '#FFFF54'],
    "Green Eggs": ['#58A866', '#AAE009', '#9EFC7D', '#FFF07A', '#FBBF51', '#FFFF00', '#009ACD', '#FF2626', '#E85AAA', '#D1C57E', '#CE95C8', '#5ABFC6'],
    "Olive Sunset": ['#990033', '#CC0033', '#FF9966', '#FFFFCC', '#CCCC99', '#CCCC33', '#999900', '#666600', '#003366', '#006699', '#3399CC', '#99CCCC'],
    "Lagoon Nebula": ['#325086', '#9ED5AE', '#D86562', '#845D4E', '#F4AD6F', '#98C8D6', '#5A272C', '#CFAD4B'],
    "Monaco": ['#EC8921', '#DB4621', '#D92130', '#38B236', '#3DBFCC', '#2A91D2', '#7378D4']
}

class FileScannerThread(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(pd.DataFrame)

    def __init__(self, directory):
        super().__init__()
        self.directory = directory

    def run(self):
        file_sizes = []
        file_names = []
        total_files = len([f for f in os.listdir(self.directory) if not f.startswith('.')])
        increment = 100 / total_files if total_files > 0 else 1

        for index, filename in enumerate(os.listdir(self.directory)):
            if filename.startswith('.'):
                continue  # Skip hidden files
            path = os.path.join(self.directory, filename)
            if os.path.isfile(path):
                file_sizes.append(os.stat(path).st_size)
                file_names.append(filename)
            self.progress.emit(int((index + 1) * increment))

        data = {'name': file_names, 'size': file_sizes}
        df = pd.DataFrame(data)
        self.result.emit(df)

class SecureDeleteThread(QThread):
    def __init__(self, file_path, method, passes):
        super().__init__()
        self.file_path = file_path
        self.method = method
        self.passes = passes

    def run(self):
        if self.method == 'zero':
            self.zero_fill()
        elif self.method == 'random':
            self.random_fill()
        elif self.method == 'dod':
            self.dod_standard()
        elif self.method == 'aes':
            self.aes_wipe()
        os.remove(self.file_path)

    def zero_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(b'\x00' * os.path.getsize(self.file_path))

    def random_fill(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(self.passes):
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def dod_standard(self):
        with open(self.file_path, "ba+", buffering=0) as f:
            for _ in range(3):  # DoD 5220.22-M standard is 3 passes
                f.seek(0)
                f.write(os.urandom(os.path.getsize(self.file_path)))

    def aes_wipe(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(self.file_path, "ba+", buffering=0) as f:
            f.seek(0)
            data = f.read()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            f.seek(0)
            f.write(encrypted_data)

class ShredSpaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ShredSpace - Advanced File Visualizer')
        self.setGeometry(100, 100, 1200, 800)
        self.current_directory = None
        self.selected_file = None
        self.settings = self.load_settings()
        self.initUI()

    def compile_user_manual(self):
        manual_directory = 'manuals'  # Directory containing markdown files
        output_file_path = os.path.join(manual_directory, 'user_manual.md')  # Path to save the compiled manual

        # Ensure the directory exists
        if not os.path.exists(manual_directory):
            os.makedirs(manual_directory)
            QMessageBox.information(self, "Directory Missing", "The manuals directory does not exist and was created. Please add markdown files.")
            return

        # Read all markdown files and compile them into one
        manual_files = [f for f in os.listdir(manual_directory) if f.endswith('.md')]
        if not manual_files:
            QMessageBox.information(self, "No Files Found", "No markdown files found in the manuals directory.")
            return

        with open(output_file_path, 'w') as outfile:
            for fname in manual_files:
                with open(os.path.join(manual_directory, fname), 'r') as infile:
                    outfile.write(infile.read() + '\n\n')

        QMessageBox.information(self, "User Manual Compiled", f"User manual has been compiled and saved as '{output_file_path}'.")

    def initUI(self):
        main_layout = QVBoxLayout()
        toolbar_layout = QHBoxLayout()

        self.load_button = QPushButton('Load Data')
        self.load_button.clicked.connect(self.load_data)
        toolbar_layout.addWidget(self.load_button)

        self.search_var = QLineEdit()
        self.search_var.textChanged.connect(self.update_search_results)
        toolbar_layout.addWidget(self.search_var)

        self.search_button = QPushButton('Search')
        self.search_button.clicked.connect(self.search_files)
        toolbar_layout.addWidget(self.search_button)

        self.delete_button = QPushButton('Delete')
        self.delete_button.clicked.connect(self.delete_file)
        self.delete_button.setEnabled(False)
        toolbar_layout.addWidget(self.delete_button)

        self.secure_delete_button = QPushButton('Secure Delete')
        self.secure_delete_button.clicked.connect(self.secure_delete_file)
        self.secure_delete_button.setEnabled(False)
        toolbar_layout.addWidget(self.secure_delete_button)

        self.progress_bar = QProgressBar()
        toolbar_layout.addWidget(self.progress_bar)

        self.passes_slider = QSlider(Qt.Horizontal, self)
        self.passes_slider.setMinimum(1)
        self.passes_slider.setMaximum(99)
        self.passes_slider.setValue(3)
        self.passes_slider.valueChanged.connect(self.update_passes)
        toolbar_layout.addWidget(self.passes_slider)

        main_layout.addLayout(toolbar_layout)

        self.canvas = FigureCanvas(plt.figure(figsize=(10, 8)))
        main_layout.addWidget(self.canvas)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.create_menu()

        self.toolbar = self.addToolBar('Main Toolbar')
        delete_action = QAction(QIcon('delete.png'), 'Delete', self)
        secure_delete_action = QAction(QIcon('secure_delete.png'), 'Secure Delete', self)
        self.toolbar.addAction(delete_action)
        self.toolbar.addAction(secure_delete_action)
        delete_action.triggered.connect(self.delete_file)
        secure_delete_action.triggered.connect(self.secure_delete_file)

        self.search_bar = QLineEdit(self)
        self.search_bar.textChanged.connect(self.update_search_results)
        self.setCentralWidget(self.search_bar)

        # Assuming you have a QListWidget or similar to display results
        self.paginated_list = PaginatedListWidget([], parent=self)
        self.setCentralWidget(self.paginated_list)

    def create_menu(self):
        menubar = self.menuBar()
        settings_menu = menubar.addMenu('Settings')

        color_theme_menu = QMenu('Color Theme', self)
        settings_menu.addMenu(color_theme_menu)

        # Monaco as a default and disabled item
        default_action = QAction('Monaco (Default)', self)
        default_action.setEnabled(False)
        color_theme_menu.addAction(default_action)

        for theme in theme_colors.keys():
            if theme != 'Monaco':
                action = QAction(theme, self)
                action.triggered.connect(lambda checked, theme=theme: self.set_color_theme(theme))
                color_theme_menu.addAction(action)

        settings_menu.addSeparator()

        sort_menu = QMenu('Sort Options', self)
        settings_menu.addMenu(sort_menu)

        # Adding more sort actions
        sort_by_name_action = QAction('Sort by Name', self)
        sort_by_size_action = QAction('Sort by Size', self)
        sort_by_type_action = QAction('Sort by Type', self)
        sort_by_date_action = QAction('Sort by Date Modified', self)

        sort_menu.addAction(sort_by_name_action)
        sort_menu.addAction(sort_by_size_action)
        sort_menu.addAction(sort_by_type_action)
        sort_menu.addAction(sort_by_date_action)

        # Connect these actions to their respective functions
        sort_by_name_action.triggered.connect(lambda: self.apply_sort('name'))
        sort_by_size_action.triggered.connect(lambda: self.apply_sort('size'))
        sort_by_type_action.triggered.connect(lambda: self.apply_sort('type'))
        sort_by_date_action.triggered.connect(lambda: self.apply_sort('date'))

        recent_scans_menu = QMenu('Recent Scans', self)
        settings_menu.addMenu(recent_scans_menu)

        self.recent_scans_actions = []
        for directory in self.settings.get('recent_scans', []):
            action = QAction(directory, self)
            action.triggered.connect(lambda checked, dir=directory: self.load_recent_scan(dir))
            recent_scans_menu.addAction(action)
            self.recent_scans_actions.append(action)

    def load_settings(self):
        try:
            with open('settings.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {'color_theme': 'Monaco', 'recent_scans': []}

    def save_settings(self):
        with open('settings.json', 'w') as f:
            json.dump(self.settings, f)

    def set_color_theme(self, theme):
        self.settings['color_theme'] = theme
        self.save_settings()
        if self.current_directory:
            self.load_data()

    def load_recent_scan(self, directory):
        self.current_directory = directory
        self.load_data()

    def load_data(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")

        if directory:
            self.current_directory = directory
            if directory not in self.settings['recent_scans']:
                self.settings['recent_scans'].insert(0, directory)
                if len(self.settings['recent_scans']) > 30:
                    self.settings['recent_scans'].pop()
                self.save_settings()
            self.scan_directory()

    def scan_directory(self):
        self.progress_bar.setValue(0)
        self.file_scanner_thread = FileScannerThread(self.current_directory)
        self.file_scanner_thread.progress.connect(self.progress_bar.setValue)
        self.file_scanner_thread.result.connect(self.display_data)
        self.file_scanner_thread.start()

    def display_data(self, df):
        self.create_interactive_treemap(df, self.settings['color_theme'])

    def create_interactive_treemap(self, data, color_scheme):
        plt.clf()
        labels = [f"{name}\n{size} bytes" for name, size in zip(data['name'], data['size'])]
        sizes = data['size']
        colors = [theme_colors[self.settings['color_theme']][int(i % len(theme_colors[self.settings['color_theme']]))] for i in range(len(data))]

        fig, ax = plt.subplots()
        squarify.plot(sizes=sizes, label=labels, color=colors, alpha=0.6, ax=ax, pad=False)
        plt.axis('off')

        # Apply gradient effect
        for rect in ax.patches:
            x, y, dx, dy = rect.get_x(), rect.get_y(), rect.get_width(), rect.get_height()
            gradient_patch = patches.Rectangle((x, y), dx, dy, color='white', alpha=0.3)
            ax.add_patch(gradient_patch)

        self.canvas.figure = fig
        self.canvas.draw()

        # Connect the click event
        self.canvas.mpl_connect('button_press_event', self.on_click)

    def apply_sort(self, sort_by):
        if not self.current_directory:
            QMessageBox.information(self, "Error", "No directory selected.")
            return

        files = os.listdir(self.current_directory)
        if sort_by == 'name':
            sorted_files = sorted(files)
        elif sort_by == 'size':
            sorted_files = sorted(files, key=lambda x: os.path.getsize(os.path.join(self.current_directory, x)))
        elif sort_by == 'type':
            sorted_files = sorted(files, key=lambda x: os.path.splitext(x)[1])
        elif sort_by == 'date':
            sorted_files = sorted(files, key=lambda x: os.path.getmtime(os.path.join(self.current_directory, x)))

        file_details = [(f, os.path.getsize(os.path.join(self.current_directory, f))) for f in sorted_files]
        df = pd.DataFrame(file_details, columns=['name', 'size'])
        self.display_data(df)

    def on_click(self, event):
        # Get the coordinates of the click
        x, y = event.xdata, event.ydata
        if x is not None and y is not None:
            # Find the rectangle that was clicked
            for rect in self.canvas.figure.axes[0].patches:
                if rect.contains_point((x, y)):
                    label = rect.get_label()
                    file_name = label.split('\n')[0]
                    self.selected_file = file_name
                    self.delete_button.setEnabled(True)
                    self.secure_delete_button.setEnabled(True)
                    QMessageBox.information(self, "File Selected", f"Selected file: {file_name}")
                    break

    def get_selected_file(self):
        return self.selected_file if self.selected_file else None

    def delete_file(self):
        selected_file = self.get_selected_file()
        if selected_file:
            file_path = os.path.join(self.current_directory, selected_file)
            os.remove(file_path)
            QMessageBox.information(self, "Success", f"Deleted {selected_file}")
            self.delete_button.setEnabled(False)
            self.secure_delete_button.setEnabled(False)

    def secure_delete_file(self):
        selected_file = self.get_selected_file()
        if selected_file:
            file_path = os.path.join(self.current_directory, selected_file)
            method = self.settings.get('secure_delete_method', 'dod')
            passes = self.passes_slider.value()

            if not self.validate_passes(passes):
                return

            self.progress_bar.setValue(0)

            self.secure_delete_thread = SecureDeleteThread(file_path, method, passes)
            self.secure_delete_thread.progress.connect(self.progress_bar.setValue)
            self.secure_delete_thread.finished.connect(self.on_secure_delete_finished)
            self.secure_delete_thread.start()

    def on_secure_delete_finished(self):
        QMessageBox.information(self, "Success", f"Securely deleted {self.selected_file}")
        self.delete_button.setEnabled(False)
        self.secure_delete_button.setEnabled(False)

    def update_passes(self, value):
        self.settings['secure_delete_passes'] = value
        self.save_settings()

    def validate_passes(self, passes):
        if not (1 <= passes <= 99):
            QMessageBox.warning(self, "Invalid Input", "Number of passes must be between 1 and 99.")
            return False
        return True

    def update_search_results(self, text):
        if not text.strip():
            self.clear_search_results()
            return

        # Assuming `self.file_list` contains all the filenames in the current directory
        filtered_files = [filename for filename in self.file_list if text.lower() in filename.lower()]
        self.display_search_results(filtered_files)

    def display_search_results(self, filtered_files):
        self.paginated_list.items = filtered_files
        self.paginated_list.current_page = 0
        self.paginated_list.update_display()

    def clear_search_results(self):
        self.paginated_list.items = []
        self.paginated_list.current_page = 0
        self.paginated_list.update_display()

    def search_files(self):
        search_term = self.search_box.text().lower()
        filtered_data = self.data[self.data['name'].str.contains(search_term, case=False, na=False)]
        
        if filtered_data.empty:
            QMessageBox.information(self, "No Results", f"No files found matching: {search_term}")
        else:
            self.create_interactive_treemap(filtered_data, 'Rainbow')
        print("Search for:", search_term)
        pass

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Down:
            self.paginated_list.list_widget.setCurrentRow(
                (self.paginated_list.list_widget.currentRow() + 1) % self.paginated_list.list_widget.count()
            )
        elif event.key() == Qt.Key_Up:
            self.paginated_list.list_widget.setCurrentRow(
                (self.paginated_list.list_widget.currentRow() - 1 + self.paginated_list.list_widget.count()) % self.paginated_list.list_widget.count()
            )
        elif event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self.select_file()

    def select_file(self):
        selected_item = self.paginated_list.list_widget.currentItem()
        if selected_item:
            selected_file = selected_item.text()
            QMessageBox.information(self, "File Selected", f"Selected file: {selected_file}")

    def setup_accessibility(self):
        self.setAccessibleName("Main Window")
        self.setAccessibleDescription("This is the main window of the application with file management features.")

    def profile_application(self, function_to_profile):
        profiler = cProfile.Profile()
        profiler.enable()
        function_to_profile()
        profiler.disable()
        stats = pstats.Stats(profiler).sort_stats('cumtime')
        stats.print_stats()

    def generate_documentation(self):
        import inspect
        import markdown2
        import os

        docstrings = []
        for name, obj in inspect.getmembers(self):
            if inspect.isfunction(obj) or inspect.ismethod(obj):
                docstring = inspect.getdoc(obj)
                if docstring:
                    docstrings.append(f"### {name}\n{docstring}\n")
                else:
                    docstrings.append(f"### {name}\nNo documentation available.\n")

        # Convert docstrings to markdown
        markdown_content = "# Auto-generated Documentation\n" + "\n".join(docstrings)
        html_content = markdown2.markdown(markdown_content)

        # Save markdown file
        with open('documentation.md', 'w') as f:
            f.write(markdown_content)

        # Save HTML file
        with open('documentation.html', 'w') as f:
            f.write(html_content)

        # Compile a user manual from markdown files
        def compile_user_manual(self):
            manual_files = [f for f in os.listdir('manuals') if f.endswith('.md')]
            with open('user_manual.md', 'w') as f:
                for manual_file in manual_files:
                    with open(os.path.join('manuals', manual_file), 'r') as mf:
                        f.write(mf.read())
                        f.write("\n\n")
            QMessageBox.information(self, "User Manual", "User manual has been compiled and saved as 'user_manual.md'.")
        import inspect
        import markdown2
        import os

        docstrings = []
        for name, obj in inspect.getmembers(self):
            if inspect.isfunction(obj) or inspect.ismethod(obj):
                docstring = inspect.getdoc(obj)
                if docstring:
                    docstrings.append(f"### {name}\n{docstring}\n")
                else:
                    docstrings.append(f"### {name}\nNo documentation available.\n")

        # Convert docstrings to markdown
        markdown_content = "# Auto-generated Documentation\n" + "\n".join(docstrings)
        html_content = markdown2.markdown(markdown_content)

        # Save markdown file
        with open('documentation.md', 'w') as f:
            f.write(markdown_content)

        # Save HTML file
        with open('documentation.html', 'w') as f:
            f.write(html_content)

        # Compile a user manual from markdown files
        def compile_user_manual(self):
            manual_files = [f for f in os.listdir('manuals') if f.endswith('.md')]
            with open('user_manual.md', 'w') as f:
                for manual_file in manual_files:
                    with open(os.path.join('manuals', manual_file), 'r') as mf:
                        f.write(mf.read())
                        f.write("\n\n")
            QMessageBox.information(self, "User Manual", "User manual has been compiled and saved as 'user_manual.md'.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = ShredSpaceApp()
    main_window.show()
    sys.exit(app.exec_())
