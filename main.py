"""
Memory Forensics Analyzer — Entry Point
=========================================
Launches the PyQt5-based forensic analysis GUI.
"""

import sys
import os

# Ensure Volatility framework directory is in path
sys.path.insert(0, r"D:\volatility3-develop")

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor, QIcon, QPainter, QPixmap, QPen
from PyQt5.QtCore import Qt
from gui.viewer import MemoryViewer


def create_app_icon():
    """Create a magnifying glass icon programmatically with QPainter."""
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    # Glass circle
    pen = QPen(QColor("#00ff41"), 4)
    painter.setPen(pen)
    painter.setBrush(QColor(0, 255, 65, 40))
    painter.drawEllipse(8, 6, 36, 36)
    # Handle
    pen.setWidth(5)
    painter.setPen(pen)
    painter.drawLine(38, 38, 54, 54)
    painter.end()
    return QIcon(pixmap)


def apply_dark_palette(app):
    """Apply a full dark palette to the application."""
    palette = QPalette()
    bg = QColor("#0d1117")
    dark = QColor("#161b22")
    mid = QColor("#21262d")
    text = QColor("#e6edf3")
    bright = QColor("#00ff41")
    dim = QColor("#8b949e")
    highlight = QColor("#1f6feb")

    palette.setColor(QPalette.Window, bg)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, bg)
    palette.setColor(QPalette.AlternateBase, dark)
    palette.setColor(QPalette.ToolTipBase, dark)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, mid)
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.BrightText, bright)
    palette.setColor(QPalette.Link, highlight)
    palette.setColor(QPalette.Highlight, highlight)
    palette.setColor(QPalette.HighlightedText, text)
    palette.setColor(QPalette.Disabled, QPalette.Text, dim)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, dim)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, dim)
    palette.setColor(QPalette.Light, mid)
    palette.setColor(QPalette.Midlight, QColor("#30363d"))
    palette.setColor(QPalette.Dark, QColor("#010409"))
    palette.setColor(QPalette.Mid, dark)
    palette.setColor(QPalette.Shadow, QColor("#000000"))
    app.setPalette(palette)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    apply_dark_palette(app)
    app.setWindowIcon(create_app_icon())

    window = MemoryViewer()
    window.show()
    sys.exit(app.exec_())