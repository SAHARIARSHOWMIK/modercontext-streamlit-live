from __future__ import annotations

import gc
import os
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import torch
import torch.nn as nn
from transformers import AutoConfig, AutoModel, AutoTokenizer

from modercontext.rcc_utils_linevul import (
    build_model_input_text,
    build_strong_security_summary_text,
    derive_pivot,
    extract_maximal_features,
    find_function_name,
    normalize_language_name,
    pack_model_input,
)

ROOT = Path(__file__).resolve().parent
MODEL_PATH = Path(os.getenv("MODERCONTEXT_MODEL_PATH", ROOT / "model" / "best_model.pt"))

MAX_LENGTH = 8192
CONTEXT_BUDGET_TOKENS = 1024
TASK_BUDGET_TOKENS = 64
HEAD_LINES = 24
TAIL_LINES = 12
EVIDENCE_WINDOW = 3

ProgressCallback = Optional[Callable[[str, int, str], None]]


class ModernBERTForClassification(nn.Module):
    def __init__(self, pretrained: str, dropout: float = 0.10, pooling: str = "cls") -> None:
        super().__init__()
        config = AutoConfig.from_pretrained(pretrained, trust_remote_code=True)
        self.encoder = AutoModel.from_config(config, trust_remote_code=True)
        hidden = getattr(self.encoder.config, "hidden_size", None) or getattr(self.encoder.config, "dim", None)
        if hidden is None:
            raise ValueError("Could not infer ModernBERT hidden size from config.")
        pooling = str(pooling).lower().strip()
        if pooling not in ("cls", "mean"):
            raise ValueError(f"Unsupported pooling mode: {pooling}")
        self.pooling = pooling
        self.dropout = nn.Dropout(float(dropout))
        self.classifier = nn.Linear(int(hidden), 2)

    @staticmethod
    def masked_mean_pool(last_hidden: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        mask = attention_mask.unsqueeze(-1).type_as(last_hidden)
        summed = (last_hidden * mask).sum(dim=1)
        denom = mask.sum(dim=1).clamp(min=1e-6)
        return summed / denom

    def forward(self, ids: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        out = self.encoder(input_ids=ids, attention_mask=mask)
        last_hidden = out.last_hidden_state
        pooled = last_hidden[:, 0, :] if self.pooling == "cls" else self.masked_mean_pool(last_hidden, mask)
        pooled = self.dropout(pooled)
        return self.classifier(pooled)


class ModerContextScanner:
    def __init__(self, progress_callback: ProgressCallback = None) -> None:
        self._emit(progress_callback, "load", 3, "Loading the vulnerability detector")
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Trained checkpoint not found at {MODEL_PATH}. Put your copied checkpoint there and name it best_model.pt.")

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        try:
            ckpt = torch.load(MODEL_PATH, map_location="cpu", weights_only=False, mmap=True)
        except TypeError:
            ckpt = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)

        for required in ("model_name", "dropout", "pooling", "state_dict"):
            if required not in ckpt:
                raise KeyError(f"Checkpoint is missing required key: {required}")

        model_name = str(ckpt["model_name"])
        self._emit(progress_callback, "load", 7, "Preparing tokenizer and model")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True, trust_remote_code=True)
        if self.tokenizer.pad_token is None:
            if self.tokenizer.eos_token is not None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            elif self.tokenizer.unk_token is not None:
                self.tokenizer.pad_token = self.tokenizer.unk_token
            else:
                raise ValueError("Tokenizer has no usable pad/eos/unk token.")
        self.tokenizer.padding_side = "right"
        self.tokenizer.model_max_length = MAX_LENGTH

        self.model = ModernBERTForClassification(
            pretrained=model_name,
            dropout=float(ckpt["dropout"]),
            pooling=str(ckpt["pooling"]),
        )
        self.model.load_state_dict(ckpt["state_dict"], strict=True)
        self.model.to(self.device)
        self.model.eval()
        del ckpt
        gc.collect()
        self._emit(progress_callback, "load", 10, "Detector ready")

    @staticmethod
    def _emit(callback: ProgressCallback, stage: str, percent: int, message: str) -> None:
        if callback is not None:
            callback(stage, int(percent), str(message))

    def analyze(self, code: str, progress_callback: ProgressCallback = None) -> Dict[str, Any]:
        started = time.perf_counter()
        self._emit(progress_callback, "validate", 15, "Validating source code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Please paste a non-empty C or C++ function.")
        code = code.strip()

        language_name = normalize_language_name(None, code=code)
        function_name = find_function_name({"code": code}, code=code) or "Unknown function"

        self._emit(progress_callback, "prepare", 32, "Pre-processing the submitted function")
        full_profile = extract_maximal_features(code=code, function_name=function_name, language_name=language_name)

        self._emit(progress_callback, "context", 55, "Analyzing security-relevant code context")
        pivot = derive_pivot(full_profile)
        security_summary = build_strong_security_summary_text(
            full_profile,
            pivot_type=str(pivot.get("pivot_type", "unknown")),
            dataset_name="linevul",
        )
        evidence_indices = list(full_profile.get("evidence", {}).get("line_indices", []))
        packed = pack_model_input(
            code=code,
            active_secctx_text=security_summary,
            tokenizer=self.tokenizer,
            max_length=MAX_LENGTH,
            context_budget_tokens=CONTEXT_BUDGET_TOKENS,
            task_budget_tokens=TASK_BUDGET_TOKENS,
            head_lines=HEAD_LINES,
            tail_lines=TAIL_LINES,
            evidence_window=EVIDENCE_WINDOW,
            important_line_indices=evidence_indices,
        )
        model_input_text = build_model_input_text(
            packed["packed_code_text"],
            packed["active_secctx_text"],
            packed["task_text"],
        )

        self._emit(progress_callback, "detect", 78, "Running vulnerability detection")
        encoded = self.tokenizer(
            model_input_text,
            truncation=True,
            max_length=MAX_LENGTH,
            padding=False,
            add_special_tokens=True,
            return_tensors="pt",
        )
        input_ids = encoded["input_ids"].to(self.device)
        attention_mask = encoded["attention_mask"].to(self.device)
        autocast_ctx = torch.autocast(device_type="cuda", dtype=torch.bfloat16) if self.device.type == "cuda" else nullcontext()
        with torch.inference_mode():
            with autocast_ctx:
                logits = self.model(input_ids, attention_mask)

        self._emit(progress_callback, "finalize", 95, "Finalizing the detection result")
        predicted_class = int(logits.argmax(dim=-1).item())
        prediction_label = "VULNERABLE" if predicted_class == 1 else "SAFE"
        self._emit(progress_callback, "complete", 100, "Analysis completed")
        return {
            "prediction_class": predicted_class,
            "prediction_label": prediction_label,
            "function_name": str(function_name),
            "language_name": str(language_name),
            "analysis_seconds": round(time.perf_counter() - started, 2),
        }
