from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from firmguard_desktop.widgets import (
    LlmTracePanel,
    PathInputRow,
    ProgressPanel,
    apply_app_theme,
    apply_window_logo,
    make_header_widget,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from esp32_firmguard.services.analysis_service import AnalysisService
from esp32_firmguard.services.training_service import TrainingService
from esp32_firmguard.services.types import AnalysisResult, FunctionFinding, TrainingResult
from esp32_firmguard.services.validate import suggest_source_root, validate_source_root
from esp32_firmguard.utils import load_config, setup_logging


def build_source_roots_map(elf_paths: List[str], source_roots: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for elf_s, root_s in zip(elf_paths, source_roots):
        root_s = (root_s or "").strip()
        if not root_s:
            continue
        elf = Path(elf_s).resolve()
        for key in (str(elf), elf.name, elf.stem, elf.parent.name):
            out[key] = [root_s]
    return out


class Worker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(int, str)
    llm_trace = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            result = self._fn(self.progress.emit, self.llm_trace.emit)
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{exc}\n{traceback.format_exc()}")


class CweLabelingSection(QGroupBox):
    def __init__(self, config: dict, parent=None):
        super().__init__("CWE labels (Excel + Ollama)", parent)
        self.config = config
        self.cwe_excel_path: Optional[str] = None
        layout = QVBoxLayout(self)
        hint = QLabel(
            "One Excel file: catalog format → Ollama applies your rules; "
            "per-function format → filled rows used, Ollama fills gaps."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        excel_row = QHBoxLayout()
        self.excel_edit = QLineEdit()
        self.excel_edit.setPlaceholderText("Required: CWE catalog or per-function labels (.xlsx)")
        self.excel_edit.textChanged.connect(self._refresh_excel_kind_label)
        excel_b = QPushButton("Browse…")
        excel_b.clicked.connect(self._pick_excel)
        excel_row.addWidget(self.excel_edit, stretch=1)
        excel_row.addWidget(excel_b)
        layout.addLayout(excel_row)

        self.excel_kind_label = QLabel("")
        self.excel_kind_label.setObjectName("muted")
        self.excel_kind_label.setWordWrap(True)
        layout.addWidget(self.excel_kind_label)

        ollama_row = QHBoxLayout()
        ollama_row.addWidget(QLabel("Ollama model:"))
        self.ollama_model_edit = QLineEdit(str(config.get("llm", {}).get("model", "llama3.2")))
        ollama_test = QPushButton("Test connection")
        ollama_test.clicked.connect(self._test_ollama)
        ollama_row.addWidget(self.ollama_model_edit, stretch=1)
        ollama_row.addWidget(ollama_test)
        layout.addLayout(ollama_row)

    def excel_path(self) -> str:
        return self.excel_edit.text().strip() or (self.cwe_excel_path or "")

    def ollama_model(self) -> Optional[str]:
        text = self.ollama_model_edit.text().strip()
        return text or None

    def _pick_excel(self):
        p, _ = QFileDialog.getOpenFileName(self, "CWE Excel", str(ROOT), "Excel (*.xlsx *.xls)")
        if p:
            self.cwe_excel_path = p
            self.excel_edit.setText(p)
            self._refresh_excel_kind_label()

    def _refresh_excel_kind_label(self):
        path = self.excel_path()
        if not path or not Path(path).is_file():
            self.excel_kind_label.setText("")
            return
        try:
            from esp32_firmguard.labeling.cwe_label_merge import resolve_excel_label_mode

            _, desc = resolve_excel_label_mode(path)
            self.excel_kind_label.setText(desc)
        except Exception as exc:
            self.excel_kind_label.setText(f"Could not read Excel: {exc}")

    def _test_ollama(self):
        from esp32_firmguard.labeling.ollama_util import check_ollama

        url = self.config.get("llm", {}).get("ollama_url", "http://localhost:11434")
        model = self.ollama_model() or "llama3.2"
        ok, msg, models = check_ollama(url, model)
        if ok:
            from esp32_firmguard.labeling.ollama_util import resolve_ollama_model

            resolved = resolve_ollama_model(model, models)
            if resolved and resolved != model:
                self.ollama_model_edit.setText(resolved.split(":")[0])
            QMessageBox.information(
                self,
                "Ollama",
                msg + "\n\nInstalled:\n" + "\n".join(models[:12]),
            )
        else:
            hint = "\n\nTip: use the exact name from `ollama list` (e.g. llama3:latest)."
            QMessageBox.warning(self, "Ollama", msg + hint)


class SourceCodeView(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Menlo", 11))
        self.setPlaceholderText("Select a finding to view source or disassembly.")

    def show_snippet(self, finding: FunctionFinding):
        self.clear()
        snip = finding.source_snippet
        if not snip or not snip.get("lines"):
            dwarf_path = finding.source_file or "(unknown)"
            header = (
                f"// {finding.name} @ {finding.address or '?'}\n"
                f"// Score {finding.score:.3f}  ·  CWE {', '.join(finding.cwe) or '—'}\n"
                f"// DWARF path: {dwarf_path}\n"
                f"// Source file not found under your Source folder.\n"
                f"// Wokwi: use …/wokwi_http_server/source (see source_root.txt).\n\n"
            )
            if finding.disassembly:
                self.setPlainText(header + finding.disassembly[:12000])
            else:
                self.setPlainText(header)
            return

        path = snip.get("resolved_path") or finding.source_file or "?"
        self.append(f"// {path}  lines {finding.line_start}-{finding.line_end}\n")
        self.append(f"// Score {finding.score:.3f}  ·  CWE {', '.join(finding.cwe) or '—'}\n\n")

        fmt_hi = QTextCharFormat()
        fmt_hi.setBackground(QColor("#5c1a1a"))
        fmt_hi.setForeground(QColor("#ffcccc"))
        fmt_norm = QTextCharFormat()
        fmt_norm.setForeground(QColor("#e0e0e0"))
        fmt_gutter = QTextCharFormat()
        fmt_gutter.setForeground(QColor("#888888"))

        for row in snip["lines"]:
            n = row["number"]
            text = row["text"]
            gutter = f"{n:5d} | "
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(gutter, fmt_gutter)
            cursor.insertText(text + "\n", fmt_hi if row.get("highlight") else fmt_norm)


class TrainTab(QWidget):
    def __init__(self, config: dict, cwe_section: CweLabelingSection, parent=None):
        super().__init__(parent)
        self.config = config
        self.cwe_section = cwe_section
        self.service = TrainingService(config)
        self._worker: Optional[Worker] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setSpacing(10)

        fw_box = QGroupBox("Training firmware (debug ELF + source per project)")
        fw_layout = QVBoxLayout(fw_box)
        hint = QLabel(
            "Add each debug ELF, then choose its source folder (project root with .c / .cpp). "
            "One row per product or build."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        fw_layout.addWidget(hint)

        self.firmware_table = QTableWidget(0, 2)
        self.firmware_table.setHorizontalHeaderLabels(["ELF file", "Source folder"])
        self.firmware_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.firmware_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.firmware_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.firmware_table.setMinimumHeight(130)
        self.firmware_table.setMaximumHeight(200)
        fw_layout.addWidget(self.firmware_table)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add ELF…")
        add_btn.clicked.connect(self._add_files)
        rm_btn = QPushButton("Remove")
        rm_btn.clicked.connect(self._remove_selected)
        root_btn = QPushButton("Choose source folder…")
        root_btn.clicked.connect(self._pick_root_for_selected)
        btn_row.addWidget(add_btn)
        btn_row.addWidget(rm_btn)
        btn_row.addWidget(root_btn)
        btn_row.addStretch()
        fw_layout.addLayout(btn_row)
        layout.addWidget(fw_box)

        self.progress = ProgressPanel()
        layout.addWidget(self.progress)

        self.train_btn = QPushButton("Train model")
        self.train_btn.setObjectName("primaryBtn")
        self.train_btn.clicked.connect(self._train)
        layout.addWidget(self.train_btn)

        layout.addStretch()
        scroll.setWidget(body)
        outer.addWidget(scroll)

    def _firmware_rows(self) -> Tuple[List[str], List[str]]:
        elves: List[str] = []
        roots: List[str] = []
        for row in range(self.firmware_table.rowCount()):
            elf_item = self.firmware_table.item(row, 0)
            root_item = self.firmware_table.item(row, 1)
            if elf_item and elf_item.text().strip():
                elves.append(elf_item.text().strip())
                roots.append(root_item.text().strip() if root_item else "")
        return elves, roots

    def _append_firmware_row(self, elf_path: str, source_root: str = "") -> None:
        elf_path = str(Path(elf_path).resolve())
        for row in range(self.firmware_table.rowCount()):
            item = self.firmware_table.item(row, 0)
            if item and item.text().strip() == elf_path:
                return
        row = self.firmware_table.rowCount()
        self.firmware_table.insertRow(row)
        self.firmware_table.setItem(row, 0, QTableWidgetItem(elf_path))
        self.firmware_table.setItem(row, 1, QTableWidgetItem(source_root))

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select debug ELF files", str(ROOT), "ELF (*.elf);;All (*)"
        )
        for p in paths:
            self._append_firmware_row(p, "")

    def _remove_selected(self):
        rows = sorted(
            {idx.row() for idx in self.firmware_table.selectionModel().selectedRows()},
            reverse=True,
        )
        for row in rows:
            self.firmware_table.removeRow(row)

    def _pick_root_for_selected(self):
        rows = self.firmware_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Source folder", "Select a row in the table first.")
            return
        row = rows[0].row()
        start = ""
        root_item = self.firmware_table.item(row, 1)
        if root_item:
            start = root_item.text()
        d = QFileDialog.getExistingDirectory(self, "Source folder for this ELF", start or str(ROOT))
        if d:
            self.firmware_table.setItem(row, 1, QTableWidgetItem(d))

    def _train(self):
        elf_paths, source_roots = self._firmware_rows()
        if not elf_paths:
            QMessageBox.warning(self, "Train", "Add at least one debug ELF.")
            return
        if any(not (r or "").strip() for r in source_roots):
            QMessageBox.warning(
                self,
                "Source folder required",
                "Each ELF needs a source folder.\nSelect a row and click “Choose source folder…”.",
            )
            return

        self.train_btn.setEnabled(False)
        self.progress.reset()
        self.progress.update_progress(0, "Starting…")
        if hasattr(self.window(), "llm_panel"):
            self.window().llm_panel.clear()

        excel = self.cwe_section.excel_path()
        if not excel:
            self.train_btn.setEnabled(True)
            self.progress.reset()
            QMessageBox.warning(self, "CWE Excel", "Select a CWE labels Excel file above.")
            return

        def train_job(emit, emit_llm):
            return self.service.train(
                elf_paths,
                source_roots_map=build_source_roots_map(elf_paths, source_roots),
                cwe_excel_path=excel,
                ollama_model=self.cwe_section.ollama_model(),
                on_progress=emit,
                on_llm_trace=emit_llm,
            )

        self._worker = Worker(train_job)
        self._worker.progress.connect(self._on_progress)
        self._worker.llm_trace.connect(self._on_llm_trace)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()

    def _on_llm_trace(self, trace: dict) -> None:
        if hasattr(self.window(), "llm_panel"):
            self.window().llm_panel.append_trace(trace)

    def _on_progress(self, percent: int, message: str) -> None:
        self.progress.update_progress(percent, message)

    def _on_done(self, result: TrainingResult):
        self.train_btn.setEnabled(True)
        self.progress.complete(f"Saved {result.model_path} · {result.function_count} functions")
        if hasattr(self.window(), "set_active_model"):
            self.window().set_active_model(result.model_path)

    def _on_fail(self, err: str):
        self.train_btn.setEnabled(True)
        self.progress.reset()
        QMessageBox.critical(self, "Training failed", err[:4000])


class TestTab(QWidget):
    def __init__(self, config: dict, cwe_section: CweLabelingSection, parent=None):
        super().__init__(parent)
        self.config = config
        self.cwe_section = cwe_section
        self.service = AnalysisService(config)
        self.elf_path: Optional[str] = None
        self.model_path: Optional[str] = None
        self.findings: List[FunctionFinding] = []
        self._worker: Optional[Worker] = None
        self._llm_log: List[dict] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        inp_box = QGroupBox("Test inputs")
        inp_grid = QGridLayout(inp_box)
        inp_grid.setHorizontalSpacing(10)
        inp_grid.setVerticalSpacing(8)

        inp_grid.addWidget(QLabel("ELF"), 0, 0)
        self.elf_row = PathInputRow("firmware.elf with debug symbols (-g)")
        self.elf_row.browse_btn.clicked.connect(self._pick_elf)
        inp_grid.addWidget(self.elf_row, 0, 1)

        inp_grid.addWidget(QLabel("Model"), 1, 0)
        self.model_row = PathInputRow("Trained user_model.pkl")
        self.model_row.browse_btn.clicked.connect(self._pick_model)
        inp_grid.addWidget(self.model_row, 1, 1)

        inp_grid.addWidget(QLabel("Source"), 2, 0)
        self.root_row = PathInputRow("Project source folder (e.g. …/wokwi_http_server/source)")
        self.root_row.browse_btn.clicked.connect(self._pick_root)
        inp_grid.addWidget(self.root_row, 2, 1)

        inp_grid.setColumnStretch(1, 1)
        layout.addWidget(inp_box)

        action_row = QHBoxLayout()
        self.run_btn = QPushButton("Analyze firmware")
        self.run_btn.setObjectName("primaryBtn")
        self.run_btn.setMinimumWidth(200)
        self.run_btn.clicked.connect(self._analyze)
        action_row.addWidget(self.run_btn)
        action_row.addStretch()
        self.progress = ProgressPanel()
        action_row.addWidget(self.progress, stretch=1)
        layout.addLayout(action_row)

        self.results_summary = QLabel("Run analysis to see ranked functions.")
        self.results_summary.setObjectName("muted")
        self.results_summary.setWordWrap(True)
        layout.addWidget(self.results_summary)

        content = QSplitter(Qt.Horizontal)
        content.setChildrenCollapsible(False)

        table_box = QGroupBox("Findings (click a row)")
        table_layout = QVBoxLayout(table_box)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Score", "Risk", "Function", "Src", "File", "Line", "CWE"]
        )
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.setMinimumWidth(420)
        self.table.itemSelectionChanged.connect(self._on_select)
        table_layout.addWidget(self.table)
        content.addWidget(table_box)

        detail_tabs = QTabWidget()
        detail_tabs.setObjectName("detailTabs")
        self.code = SourceCodeView()
        self.code.setMinimumHeight(280)
        detail_tabs.addTab(self.code, "Source / disasm")

        self.llm_selected = LlmTracePanel(compact=True, title="LLM (selected function)")
        detail_tabs.addTab(self.llm_selected, "LLM label")

        self.llm_run_log = LlmTracePanel(compact=True, title="LLM (run log)")
        detail_tabs.addTab(self.llm_run_log, "LLM log")

        content.addWidget(detail_tabs)
        content.setStretchFactor(0, 3)
        content.setStretchFactor(1, 2)
        content.setSizes([560, 440])
        layout.addWidget(content, stretch=1)

    def set_model_path(self, path: str):
        self.model_path = path
        self.model_row.setText(path)

    def _set_path_row(self, row: PathInputRow, path: str) -> None:
        row.setText(path)

    def _pick_elf(self):
        p, _ = QFileDialog.getOpenFileName(self, "ELF", str(ROOT), "ELF (*.elf)")
        if p:
            self.elf_path = p
            self._set_path_row(self.elf_row, p)
            suggested = suggest_source_root(p)
            if suggested and not self.root_row.text():
                self._set_path_row(self.root_row, suggested)

    def _pick_model(self):
        p, _ = QFileDialog.getOpenFileName(self, "Model", str(ROOT / "output" / "models"), "Pickle (*.pkl)")
        if p:
            self.model_path = p
            self._set_path_row(self.model_row, p)

    def _pick_root(self):
        d = QFileDialog.getExistingDirectory(self, "Source folder")
        if d:
            self._set_path_row(self.root_row, d)

    def _analyze(self):
        elf = self.elf_row.text() or self.elf_path
        if not elf:
            QMessageBox.warning(self, "Test", "Choose an ELF file.")
            return
        model = self.model_row.text() or self.model_path
        root = self.root_row.text()
        if not root:
            QMessageBox.warning(self, "Test", "Choose a source folder for this ELF.")
            return
        try:
            root = validate_source_root(root)
            self._set_path_row(self.root_row, root)
        except ValueError as exc:
            suggested = suggest_source_root(elf)
            extra = f"\n\nSuggested path:\n{suggested}" if suggested else ""
            QMessageBox.warning(self, "Source folder", f"{exc}{extra}")
            return

        excel = self.cwe_section.excel_path()
        if not excel:
            QMessageBox.warning(self, "CWE Excel", "Select a CWE labels Excel file above.")
            return

        self.run_btn.setEnabled(False)
        self.progress.reset()
        self.table.setRowCount(0)
        self.results_summary.setText("Analyzing…")
        self._llm_log.clear()
        self.llm_run_log.clear()
        self.llm_selected.clear()

        def analyze_job(emit, emit_llm):
            return self.service.analyze(
                elf,
                model_path=model,
                source_roots=[root],
                findings_source_only=False,
                on_progress=emit,
                cwe_excel_path=excel,
                ollama_model=self.cwe_section.ollama_model(),
                ollama_url=self.config.get("llm", {}).get("ollama_url"),
                on_llm_trace=emit_llm,
            )

        self._worker = Worker(analyze_job)
        self._worker.progress.connect(self._on_progress)
        self._worker.llm_trace.connect(self._on_llm_trace)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()

    def _on_llm_trace(self, trace: dict) -> None:
        self._llm_log.append(trace)
        self.llm_run_log.append_trace(trace)

    def _on_progress(self, percent: int, message: str) -> None:
        self.progress.update_progress(percent, message)

    def _finding_for_table_row(self, row: int) -> Optional[FunctionFinding]:
        item = self.table.item(row, 2)
        if item is None:
            return None
        func_id = item.data(Qt.UserRole)
        if func_id:
            for f in self.findings:
                if f.func_id == func_id:
                    return f
        if 0 <= row < len(self.findings):
            return self.findings[row]
        return None

    def _on_done(self, result: AnalysisResult):
        self.run_btn.setEnabled(True)
        self.findings = result.findings
        n = len(self.findings)
        mapped_snip = sum(
            1 for f in self.findings if f.source_snippet and f.source_snippet.get("lines")
        )
        summary = (
            f"{n} functions ranked · {result.vulnerable_count} flagged VULN · "
            f"{result.functions_with_source}/{result.functions_total} DWARF-mapped · "
            f"{mapped_snip} with readable source"
        )
        self.progress.complete("Done")
        self.results_summary.setText(summary)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(n)
        for i, f in enumerate(self.findings):
            line = ""
            if f.line_start is not None:
                line = str(f.line_start)
                if f.line_end and f.line_end != f.line_start:
                    line += f"-{f.line_end}"
            has_src = bool(f.source_snippet and f.source_snippet.get("lines"))
            vals = [
                f"{f.score:.3f}",
                "VULN" if f.is_vulnerable else "ok",
                f.name,
                "yes" if has_src else "no",
                (f.resolved_source_path or f.source_file or "—").split("/")[-1][:40],
                line or "—",
                ", ".join(f.cwe[:3]) or "—",
            ]
            for col, text in enumerate(vals):
                item = QTableWidgetItem(text)
                if col == 2:
                    item.setData(Qt.UserRole, f.func_id)
                if col == 0:
                    item.setData(Qt.UserRole + 1, f.score)
                if f.is_vulnerable:
                    item.setBackground(QColor("#8b2e2e"))
                    item.setForeground(QColor("#ffffff"))
                elif not has_src:
                    item.setForeground(QColor("#999999"))
                self.table.setItem(i, col, item)
        self.table.setSortingEnabled(True)
        if self.findings:
            self.table.selectRow(0)
            self.table.scrollToItem(self.table.item(0, 0))
        else:
            self.results_summary.setText("No findings returned.")

    def _on_fail(self, err: str):
        self.run_btn.setEnabled(True)
        self.progress.reset()
        self.results_summary.setText("Analysis failed.")
        QMessageBox.critical(self, "Analysis failed", err[:4000])

    def _on_select(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        f = self._finding_for_table_row(rows[0].row())
        if f is None:
            return
        self.code.show_snippet(f)
        self.llm_selected.show_trace(f.llm_trace)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ESP32 FirmGuard")
        self.setMinimumSize(1120, 820)
        self.resize(1280, 920)
        setup_logging("INFO")
        self.config = load_config(str(ROOT / "configs" / "config.yaml"))

        central = QWidget()
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(12, 8, 12, 10)
        root_layout.setSpacing(6)

        root_layout.addWidget(make_header_widget(ROOT, logo_px=120))

        self.cwe_section = CweLabelingSection(self.config)
        root_layout.addWidget(self.cwe_section)

        self.tabs = QTabWidget()
        self.train_tab = TrainTab(self.config, self.cwe_section)
        self.test_tab = TestTab(self.config, self.cwe_section)
        self.tabs.addTab(self.train_tab, "Train")
        self.tabs.addTab(self.test_tab, "Test")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        root_layout.addWidget(self.tabs, stretch=1)

        self.llm_panel = LlmTracePanel()
        self.llm_panel.hide()
        root_layout.addWidget(self.llm_panel, stretch=0)

        self.setCentralWidget(central)
        apply_window_logo(self, ROOT)
        self._on_tab_changed(0)

        default_model = ROOT / "output" / "models" / "user_model.pkl"
        if default_model.is_file():
            self.set_active_model(str(default_model))

    def _on_tab_changed(self, index: int) -> None:
        self.llm_panel.setVisible(index == 0)
        if index == 0:
            self.llm_panel.setMaximumHeight(160)
        else:
            self.tabs.setFocus()

    def set_active_model(self, path: str):
        self.test_tab.set_model_path(path)


def main():
    app = QApplication(sys.argv)
    apply_app_theme(app)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
