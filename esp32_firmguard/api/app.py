from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from esp32_firmguard.services.analysis_service import AnalysisService
from esp32_firmguard.services.training_service import TrainingService
from esp32_firmguard.utils import load_config, setup_logging

setup_logging("INFO")
config = load_config()
training = TrainingService(config)
analysis = AnalysisService(config)

app = FastAPI(title="ESP32 FirmGuard API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/train")
async def train_endpoint(
    files: List[UploadFile] = File(...),
    cwe_excel: UploadFile = File(..., description="CWE catalog or per-function labels Excel"),
    validation_split: float = Form(0.2),
    model_name: str = Form("user_model.pkl"),
    ollama_model: Optional[str] = Form(None),
):
    if not files:
        raise HTTPException(400, "Upload at least one debug ELF")
    tmp = Path(tempfile.mkdtemp(prefix="firmguard_train_"))
    paths: List[Path] = []
    try:
        for uf in files:
            dest = tmp / uf.filename
            with open(dest, "wb") as out:
                shutil.copyfileobj(uf.file, out)
            paths.append(dest)
        excel_dest = tmp / (cwe_excel.filename or "cwe_labels.xlsx")
        with open(excel_dest, "wb") as out:
            shutil.copyfileobj(cwe_excel.file, out)
        result = training.train(
            paths,
            validation_split=validation_split,
            model_name=model_name,
            cwe_excel_path=str(excel_dest),
            ollama_model=ollama_model,
        )
        return result.to_dict()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@app.post("/analyze")
async def analyze_endpoint(
    file: UploadFile = File(...),
    cwe_excel: UploadFile = File(..., description="CWE catalog or per-function labels Excel"),
    model_path: Optional[str] = Form(None),
    source_root: Optional[str] = Form(None),
    ollama_model: Optional[str] = Form(None),
):
    tmp = Path(tempfile.mkdtemp(prefix="firmguard_test_"))
    dest = tmp / file.filename
    try:
        with open(dest, "wb") as out:
            shutil.copyfileobj(file.file, out)
        roots = [source_root] if source_root else None
        excel_dest = tmp / (cwe_excel.filename or "cwe_labels.xlsx")
        with open(excel_dest, "wb") as out:
            shutil.copyfileobj(cwe_excel.file, out)
        result = analysis.analyze(
            dest,
            model_path=model_path,
            source_roots=roots,
            cwe_excel_path=str(excel_dest),
            ollama_model=ollama_model,
        )
        return result.to_dict()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc
