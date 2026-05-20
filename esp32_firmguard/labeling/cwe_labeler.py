import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional

from .ollama_util import ollama_chat

logger = logging.getLogger(__name__)

LabelProgressCallback = Callable[[int, int, str], None]
LlmTraceCallback = Callable[[Dict[str, Any]], None]

_SYSTEM = (
    "You label ESP32 firmware functions with CWE IDs. "
    'Return ONLY a JSON array of CWE IDs, e.g. ["CWE-120"] or [].'
)


class CWELabeler:
    def __init__(
        self,
        config: Dict[str, Any],
        cwe_catalog=None,
        trace_callback: Optional[LlmTraceCallback] = None,
    ):
        self.config = config
        self.cwe_catalog = cwe_catalog
        self.trace_callback = trace_callback
        llm = config.get("llm", {})
        self.model = llm.get("model", "llama3.2")
        self.temperature = float(llm.get("temperature", 0.3))
        self.ollama_url = llm.get("ollama_url", "http://localhost:11434")
        self.ollama_timeout = float(llm.get("ollama_timeout", 120))
        if cwe_catalog is not None and getattr(cwe_catalog, "cwe_ids", None):
            self.cwe_categories = list(cwe_catalog.cwe_ids)
        else:
            self.cwe_categories = list(llm.get("cwe_categories") or [])

    def label(
        self,
        firmware_obj,
        progress_callback: Optional[LabelProgressCallback] = None,
        trace_callback: Optional[LlmTraceCallback] = None,
    ) -> Dict[str, List[str]]:
        functions = firmware_obj.functions or {}
        if not functions:
            return {}

        labels: Dict[str, List[str]] = {}
        items = list(functions.items())
        trace_cb = trace_callback or self.trace_callback

        for idx, (func_id, func_info) in enumerate(items, start=1):
            if progress_callback:
                name = func_info.get("name") or func_id
                progress_callback(idx - 1, len(items), f"CWE: {name}")
            labels[func_id] = self._label_function(func_id, func_info, trace_cb)

        if progress_callback and items:
            progress_callback(len(items), len(items), "CWE labeling complete")
        return labels

    def _label_function(
        self,
        func_id: str,
        func_info: Dict[str, Any],
        trace_callback: Optional[LlmTraceCallback],
    ) -> List[str]:
        try:
            cwes, raw = self._label_with_llm(func_info)
            note = ""
            if not cwes and self.cwe_catalog is not None:
                cwes = self.cwe_catalog.signal_matches(func_info)
                if not cwes:
                    cwes = self.cwe_catalog.heuristic_hints(func_info)
                if cwes:
                    note = f"\n[catalog fallback: {', '.join(cwes)}]"
            self._emit_trace(func_id, func_info, raw + note, cwes, trace_callback)
            return cwes
        except Exception as exc:
            raise RuntimeError(f"Ollama labeling failed for {func_id}: {exc}") from exc

    def _label_with_llm(self, func_info: Dict[str, Any]) -> tuple[List[str], str]:
        prompt = self._build_prompt(func_info)
        raw = ollama_chat(
            prompt,
            system=_SYSTEM,
            model=self.model,
            base_url=self.ollama_url,
            temperature=self.temperature,
            timeout=self.ollama_timeout,
        )
        allowed = list(self.cwe_categories) if self.cwe_categories else None
        return self.parse_llm_cwe_response(raw, allowed=allowed), raw

    @staticmethod
    def parse_llm_cwe_response(response: str, allowed: Optional[List[str]] = None) -> List[str]:
        if not response:
            return []
        text = response.strip()
        if "```" in text:
            for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE):
                text = block.strip()
                break
        try:
            match = re.search(r"\[[\s\S]*?\]", text)
            if match:
                data = json.loads(match.group())
                if isinstance(data, list):
                    out = []
                    for item in data:
                        s = str(item).strip().upper()
                        if re.match(r"CWE-\d+", s):
                            out.append(s if s.startswith("CWE-") else f"CWE-{s.split('-')[-1]}")
                    if allowed:
                        allow = {a.upper() for a in allowed}
                        out = [c for c in out if c in allow]
                    return sorted(set(out))
        except json.JSONDecodeError:
            pass
        out = sorted({f"CWE-{m.split('-')[-1]}" for m in re.findall(r"CWE-\d+", text, re.IGNORECASE)})
        if allowed:
            allow = {a.upper() for a in allowed}
            out = [c for c in out if c in allow]
        return out

    def _build_prompt(self, func_info: Dict[str, Any]) -> str:
        name = func_info.get("name", "unknown")
        calls = func_info.get("calls", [])
        strings = func_info.get("strings", [])
        asm = (func_info.get("disassembly") or "")[:2500]
        source_file = func_info.get("source_file") or ""
        line_start = func_info.get("line_start")
        line_end = func_info.get("line_end")

        catalog_block = ""
        hints: List[str] = []
        if self.cwe_catalog is not None:
            catalog_block = self.cwe_catalog.prompt_block()
            hints = self.cwe_catalog.heuristic_hints(func_info)

        loc = ""
        if source_file:
            loc = f"\nSource: {source_file}"
            if line_start:
                loc += f" lines {line_start}-{line_end or line_start}"

        source_block = ""
        snip = func_info.get("source_snippet") or {}
        for row in (snip.get("lines") or [])[:40]:
            source_block += f"  {row.get('number', '?')}: {row.get('text', '')}\n"
        if source_block:
            path = snip.get("resolved_path") or source_file or "?"
            source_block = f"\nSource ({path}):\n{source_block}"

        hints_line = f"\nConsider: {', '.join(hints)}\n" if hints else ""
        allowed = ", ".join(self.cwe_categories) if self.cwe_categories else "(see catalog)"

        return (
            f"Assign CWE IDs for this ESP32 function.\n\n"
            f"{catalog_block}{hints_line}\n"
            f"Function: {name}\n"
            f"Calls: {', '.join(calls) if calls else '(none)'}\n"
            f"Strings: {', '.join(strings[:20]) if strings else '(none)'}{loc}\n"
            f"{source_block}\n"
            f"Disassembly:\n{asm or '(none)'}\n\n"
            f"Allowed: {allowed}\n"
            f"Reply with ONLY a JSON array."
        )

    def _emit_trace(
        self,
        func_id: str,
        func_info: Dict[str, Any],
        raw: str,
        cwes: List[str],
        trace_callback: Optional[LlmTraceCallback],
    ) -> None:
        trace = {
            "func_id": func_id,
            "function_name": func_info.get("name") or func_id,
            "provider": "ollama",
            "model": self.model,
            "raw_response": (raw or "")[:8000],
            "parsed_cwe": list(cwes),
        }
        func_info["llm_trace"] = trace
        if trace_callback:
            trace_callback(trace)
