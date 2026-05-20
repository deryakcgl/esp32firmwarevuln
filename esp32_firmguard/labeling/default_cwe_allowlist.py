from __future__ import annotations

from typing import Any, Dict, List, Optional

from .cwe_catalog import CweCatalog, CweCatalogEntry

_DEFAULT_ENTRIES: List[Dict[str, str]] = [
    {
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size",
        "detection_signals": "strcpy,sprintf,gets,scanf,memcpy,vsprintf,snprintf",
        "llm_labeling_rule": "Assign if unsafe C string/buffer copies appear in calls or disassembly.",
    },
    {
        "cwe_id": "CWE-787",
        "cwe_name": "Out-of-bounds Write",
        "detection_signals": "memcpy,memmove,memset,array,index,offset,bounds",
        "llm_labeling_rule": "Assign if memory writes may exceed buffer bounds.",
    },
    {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "detection_signals": "free,malloc,calloc,realloc,heap",
        "llm_labeling_rule": "Assign if free/malloc pairing or pointer use after free is plausible.",
    },
    {
        "cwe_id": "CWE-190",
        "cwe_name": "Integer Overflow",
        "detection_signals": "malloc,size,length,multiply,overflow",
        "llm_labeling_rule": "Assign if size calculations feed allocations or loops.",
    },
    {
        "cwe_id": "CWE-79",
        "cwe_name": "Cross-site Scripting",
        "detection_signals": "http,html,uri,url,web,httpd,request,response",
        "llm_labeling_rule": "Assign for web/HTTP handlers that emit or parse untrusted text.",
    },
    {
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
        "detection_signals": "sql,query,database,sqlite",
        "llm_labeling_rule": "Assign if SQL strings are built from external input.",
    },
    {
        "cwe_id": "CWE-78",
        "cwe_name": "OS Command Injection",
        "detection_signals": "system,popen,exec,shell,command",
        "llm_labeling_rule": "Assign if external input reaches command execution.",
    },
    {
        "cwe_id": "CWE-22",
        "cwe_name": "Path Traversal",
        "detection_signals": "path,file,open,read,../,spiffs,fatfs",
        "llm_labeling_rule": "Assign if file paths from users are used without normalization.",
    },
    {
        "cwe_id": "CWE-311",
        "cwe_name": "Missing Encryption",
        "detection_signals": "password,secret,key,token,auth,ssl,tls",
        "llm_labeling_rule": "Assign if sensitive data is handled without crypto/TLS.",
    },
    {
        "cwe_id": "CWE-798",
        "cwe_name": "Hard-coded Credentials",
        "detection_signals": "password,secret,api_key,token,admin,default",
        "llm_labeling_rule": "Assign if literals look like embedded credentials.",
    },
    {
        "cwe_id": "CWE-362",
        "cwe_name": "Race Condition",
        "detection_signals": "mutex,lock,thread,task,queue,shared,interrupt",
        "llm_labeling_rule": "Assign if shared state is touched without clear locking on ESP32.",
    },
    {
        "cwe_id": "CWE-125",
        "cwe_name": "Out-of-bounds Read",
        "detection_signals": "read,recv,parse,memcpy,strlen,array",
        "llm_labeling_rule": "Assign if reads may exceed buffer bounds.",
    },
]


def build_fallback_catalog(config: Optional[Dict[str, Any]] = None) -> CweCatalog:
    cfg = (config or {}).get("llm") or {}
    custom_ids: List[str] = list(cfg.get("cwe_categories") or [])
    entries: List[CweCatalogEntry] = []
    if custom_ids:
        for cid in custom_ids:
            entries.append(CweCatalogEntry(cwe_id=cid, cwe_name=cid, use_as_label=True))
    else:
        for row in _DEFAULT_ENTRIES:
            entries.append(
                CweCatalogEntry(
                    cwe_id=row["cwe_id"],
                    cwe_name=row.get("cwe_name", ""),
                    detection_signals=row.get("detection_signals", ""),
                    llm_labeling_rule=row.get("llm_labeling_rule", ""),
                    use_as_label=True,
                    priority=50,
                )
            )
    return CweCatalog(entries=entries, source_path="(built-in fallback)")
