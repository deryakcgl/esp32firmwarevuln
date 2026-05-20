from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


def logo_path(root: Path) -> Path:
    return root / "logo" / "logo.png"


def apply_window_logo(window, root: Path) -> None:
    path = logo_path(root)
    if path.is_file():
        window.setWindowIcon(QIcon(str(path)))


def apply_app_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(
        """
        QMainWindow, QWidget {
            background-color: #16181d;
            color: #eceff4;
            font-size: 13px;
        }
        QGroupBox {
            font-weight: 600;
            font-size: 13px;
            border: 1px solid #2e3440;
            border-radius: 10px;
            margin-top: 14px;
            padding: 16px 12px 12px 12px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #88c0d0;
        }
        QTabWidget::pane {
            border: 1px solid #2e3440;
            border-radius: 8px;
            top: -1px;
            background: #1e2128;
        }
        QTabBar::tab {
            background: #252830;
            color: #aeb3bb;
            padding: 10px 22px;
            margin-right: 4px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
        }
        QTabBar::tab:selected {
            background: #1e2128;
            color: #eceff4;
            font-weight: 600;
        }
        QLineEdit, QComboBox, QTextEdit, QTableWidget {
            background-color: #252830;
            border: 1px solid #3b4252;
            border-radius: 6px;
            padding: 6px 8px;
            color: #eceff4;
            selection-background-color: #5e81ac;
        }
        QTableWidget {
            gridline-color: #2e3440;
        }
        QHeaderView::section {
            background-color: #2e3440;
            color: #d8dee9;
            padding: 8px;
            border: none;
            font-weight: 600;
        }
        QPushButton {
            background-color: #5e81ac;
            color: #eceff4;
            border: none;
            border-radius: 6px;
            padding: 8px 14px;
            font-weight: 600;
        }
        QPushButton:hover { background-color: #81a1c1; }
        QPushButton:pressed { background-color: #4c6a8a; }
        QPushButton:disabled { background-color: #3b4252; color: #6b7280; }
        QPushButton#primaryBtn {
            background-color: #a3be8c;
            color: #1a1d23;
            font-size: 14px;
            padding: 10px 20px;
        }
        QPushButton#primaryBtn:hover { background-color: #b8d4a3; }
        QProgressBar {
            border: 1px solid #3b4252;
            border-radius: 6px;
            text-align: center;
            background: #252830;
            height: 22px;
        }
        QProgressBar::chunk {
            background-color: #88c0d0;
            border-radius: 5px;
        }
        QLabel#muted { color: #9ca3af; font-size: 12px; }
        QLabel#appTitle {
            font-size: 26px;
            font-weight: 700;
            color: #eceff4;
        }
        QLabel#appSubtitle {
            font-size: 12px;
            color: #9ca3af;
        }
        QScrollArea {
            border: none;
            background: transparent;
        }
        QSplitter::handle {
            background-color: #3b4252;
        }
        QSplitter::handle:horizontal { width: 4px; }
        QSplitter::handle:vertical { height: 4px; }
        QTabWidget#detailTabs::pane {
            border: 1px solid #2e3440;
            border-radius: 6px;
            background: #1a1d23;
        }
        QTabWidget#detailTabs QTabBar::tab {
            padding: 6px 14px;
            font-size: 12px;
        }
        """
    )


class PathInputRow(QWidget):
    def __init__(self, placeholder: str = "", browse_label: str = "Browse…", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.setClearButtonEnabled(True)
        self.browse_btn = QPushButton(browse_label)
        self.browse_btn.setFixedWidth(88)
        layout.addWidget(self.edit, stretch=1)
        layout.addWidget(self.browse_btn)

    def text(self) -> str:
        return self.edit.text().strip()

    def setText(self, value: str) -> None:
        self.edit.setText(value)
        self.edit.setToolTip(value)


def make_header_widget(root: Path, *, logo_px: int = 200) -> QWidget:
    w = QWidget()
    w.setObjectName("appHeader")
    col = QVBoxLayout(w)
    col.setContentsMargins(8, 8, 8, 4)
    col.setSpacing(4)
    col.setAlignment(Qt.AlignHCenter)

    path = logo_path(root)
    if path.is_file():
        pix = QPixmap(str(path))
        if not pix.isNull():
            logo_lbl = QLabel()
            logo_lbl.setAlignment(Qt.AlignCenter)
            logo_lbl.setPixmap(
                pix.scaled(logo_px, logo_px, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
            col.addWidget(logo_lbl)

    title = QLabel("ESP32 FirmGuard")
    title.setObjectName("appTitle")
    title.setAlignment(Qt.AlignCenter)
    col.addWidget(title)

    sub = QLabel("Firmware vulnerability analysis — train on debug ELFs, test with source context")
    sub.setObjectName("appSubtitle")
    sub.setAlignment(Qt.AlignCenter)
    sub.setWordWrap(True)
    col.addWidget(sub)
    return w


class LlmTracePanel(QGroupBox):
    def __init__(self, parent=None, *, compact: bool = False, title: str = "LLM responses"):
        super().__init__(title, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        if not compact:
            self.hint = QLabel("Ollama output while labeling CWEs (Train) or for selected row (Test).")
            self.hint.setObjectName("muted")
            self.hint.setWordWrap(True)
            layout.addWidget(self.hint)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlaceholderText("No LLM output yet.")
        self.text.setMinimumHeight(100 if compact else 72)
        if not compact:
            self.text.setMaximumHeight(160)
        layout.addWidget(self.text, stretch=1)

    def clear(self) -> None:
        self.text.clear()

    def append_trace(self, trace: dict) -> None:
        block = format_llm_trace(trace)
        if self.text.toPlainText():
            self.text.append("\n" + ("─" * 40) + "\n")
        self.text.append(block)
        self.text.verticalScrollBar().setValue(self.text.verticalScrollBar().maximum())

    def show_trace(self, trace: Optional[dict]) -> None:
        self.clear()
        if trace:
            self.text.setPlainText(format_llm_trace(trace))
        else:
            self.text.setPlainText("(No LLM trace for this function.)")


def format_llm_trace(trace: dict) -> str:
    name = trace.get("function_name") or trace.get("func_id") or "?"
    provider = trace.get("provider") or "?"
    model = trace.get("model") or ""
    parsed = trace.get("parsed_cwe") or []
    raw = (trace.get("raw_response") or "").strip()
    lines = [f"▸ {name}", f"  Provider: {provider}" + (f"  ·  {model}" if model else "")]
    lines.append(f"  CWE: {', '.join(parsed) if parsed else '(none)'}")
    if raw:
        lines.append("  Response:")
        for ln in raw.splitlines()[:25]:
            lines.append(f"    {ln}")
        if raw.count("\n") > 25:
            lines.append("    …")
    return "\n".join(lines)


class ProgressPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setFormat("%p%")
        self.bar.setTextVisible(True)
        self.status = QLabel("")
        self.status.setObjectName("muted")
        layout.addWidget(self.bar)
        layout.addWidget(self.status)
        self.hide()

    def reset(self) -> None:
        self.bar.setValue(0)
        self.status.setText("")
        self.hide()

    def update_progress(self, percent: int, message: str) -> None:
        self.show()
        self.bar.setValue(max(0, min(100, percent)))
        self.status.setText(message)

    def complete(self, message: str = "Done") -> None:
        self.bar.setValue(100)
        self.status.setText(message)
