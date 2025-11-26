"""LLM-based CWE labeling for firmware functions"""

import logging
from typing import Dict, Any, List, Optional
import json
import os

logger = logging.getLogger(__name__)


class CWELabeler:
    """Label functions with CWE categories using LLM"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.llm_config = config.get("llm", {})
        self.provider = self.llm_config.get("provider", "ollama")
        self.model = self.llm_config.get("model", "llama3")
        self.temperature = self.llm_config.get("temperature", 0.3)
        self.cwe_categories = self.llm_config.get("cwe_categories", [])
        
        # Get API key based on provider
        if self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY") or self.llm_config.get("api_key")
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY") or self.llm_config.get("api_key")
        elif self.provider == "ollama":
            # Ollama doesn't need API key, uses local server
            self.api_key = None
            self.ollama_url = self.llm_config.get("ollama_url", "http://localhost:11434")
        else:
            self.api_key = self.llm_config.get("api_key")
        
        # Mock mode if no API key (except Ollama which doesn't need one)
        self.mock_mode = (self.api_key is None and self.provider != "ollama")
        if self.mock_mode:
            logger.warning(f"No API key found for {self.provider}. Using advanced pattern-based labeling.")
        elif self.provider == "ollama":
            logger.info(f"Using Ollama with model: {self.model} at {self.ollama_url}")
    
    def label(self, firmware_obj) -> Dict[str, List[str]]:
        """
        Label each function with CWE categories.
        
        Args:
            firmware_obj: FirmwareObject with functions to label
        
        Returns:
            Dictionary mapping function_id -> list of CWE IDs
        """
        functions = firmware_obj.functions
        if not functions:
            logger.warning("No functions found in firmware object")
            return {}
        
        labels = {}
        
        for func_id, func_info in functions.items():
            cwe_labels = self._label_function(func_id, func_info)
            labels[func_id] = cwe_labels
        
        logger.info(f"Labeled {len(labels)} functions with CWE categories")
        return labels
    
    def _label_function(self, func_id: str, func_info: Dict[str, Any]) -> List[str]:
        """Label a single function with CWE categories"""
        if not self.mock_mode:
            # Try real LLM API first
            try:
                return self._label_with_llm(func_id, func_info)
            except Exception as e:
                logger.warning(f"LLM API call failed for {func_id}: {e}. Falling back to pattern-based labeling.")
        
        # Use advanced pattern-based labeling (research-quality)
        return self._advanced_pattern_labeling(func_id, func_info)
    
    def _label_with_llm(self, func_id: str, func_info: Dict[str, Any]) -> List[str]:
        """Label function using real LLM API"""
        prompt = self._build_prompt(func_info)
        response = self._call_llm_api(prompt)
        
        # Parse LLM response
        try:
            # Try to extract JSON array from response
            import re
            # Look for JSON array pattern
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                try:
                    cwe_list = json.loads(json_match.group())
                    if isinstance(cwe_list, list):
                        return [str(cwe) for cwe in cwe_list if str(cwe).startswith("CWE-")]
                except json.JSONDecodeError:
                    # Try to find CWE IDs directly in text
                    cwe_pattern = r'CWE-\d+'
                    cwe_matches = re.findall(cwe_pattern, response)
                    if cwe_matches:
                        return list(set(cwe_matches))  # Remove duplicates
        except Exception as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Fallback: extract CWE IDs directly
            try:
                import re
                cwe_pattern = r'CWE-\d+'
                cwe_matches = re.findall(cwe_pattern, response)
                if cwe_matches:
                    return list(set(cwe_matches))
            except:
                pass
        
        return []
    
    def _advanced_pattern_labeling(self, func_id: str, func_info: Dict[str, Any]) -> List[str]:
        """
        Advanced pattern-based CWE labeling using comprehensive vulnerability patterns.
        Research-quality heuristics based on real-world vulnerability patterns.
        """
        func_name = func_info.get("name", "").lower()
        calls = [c.lower() for c in func_info.get("calls", [])]
        strings = [s.lower() for s in func_info.get("strings", [])]
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        entropy = func_info.get("entropy", 6.5)
        
        cwe_labels = []
        vulnerability_score = 0.0
        
        # CWE-120: Buffer Overflow (Classic)
        buffer_overflow_indicators = {
            "dangerous_calls": ["strcpy", "sprintf", "gets", "scanf", "vsprintf"],
            "context_keywords": ["buffer", "copy", "input", "read", "receive"],
            "risk_multiplier": 1.0
        }
        if any(dc in calls for dc in buffer_overflow_indicators["dangerous_calls"]):
            if any(kw in func_name for kw in buffer_overflow_indicators["context_keywords"]):
                cwe_labels.append("CWE-120")
                vulnerability_score += 0.8
            elif "memcpy" in calls and size > 256:  # Large memcpy without bounds check
                cwe_labels.append("CWE-120")
                vulnerability_score += 0.6
        
        # CWE-787: Out-of-bounds Write
        if any(unsafe in calls for unsafe in ["memcpy", "strcpy", "memset", "memmove"]):
            if any(idx in func_name for idx in ["array", "index", "offset", "ptr"]):
                cwe_labels.append("CWE-787")
                vulnerability_score += 0.7
            elif entropy > 7.5 and size > 200:  # High entropy + unsafe operations
                cwe_labels.append("CWE-787")
                vulnerability_score += 0.5
        
        # CWE-416: Use After Free
        if "free" in calls and "malloc" in calls:
            # Multiple malloc/free pairs suggest potential UAF
            malloc_count = sum(1 for c in calls if "malloc" in c or "calloc" in c or "realloc" in c)
            free_count = sum(1 for c in calls if "free" in c)
            if malloc_count > 1 and free_count > 1:
                cwe_labels.append("CWE-416")
                vulnerability_score += 0.6
            elif any(ptr in func_name for ptr in ["pointer", "ptr", "deref", "ref"]):
                cwe_labels.append("CWE-416")
                vulnerability_score += 0.7
        
        # CWE-190: Integer Overflow / Underflow
        if any(math_op in func_name for math_op in ["add", "multiply", "calculate", "compute", "size", "length"]):
            if "malloc" in calls or "calloc" in calls:
                # Size calculation before allocation
                cwe_labels.append("CWE-190")
                vulnerability_score += 0.6
            elif any(arith in calls for arith in ["*", "+", "-", "multiply", "add"]):
                cwe_labels.append("CWE-190")
                vulnerability_score += 0.5
        
        # CWE-79: Cross-site Scripting (XSS) - for web-related functions
        web_indicators = ["http", "web", "html", "url", "request", "response", "header"]
        if any(web in func_name or any(web in s for s in strings) for web in web_indicators):
            if any(input_kw in func_name for input_kw in ["input", "parse", "process", "handle"]):
                if "strcpy" in calls or "sprintf" in calls:  # Unsafe string operations
                    cwe_labels.append("CWE-79")
                    vulnerability_score += 0.7
        
        # CWE-89: SQL Injection
        if any(db in func_name or any(db in s for s in strings) for db in ["sql", "query", "database", "db"]):
            if any(exec_kw in func_name for exec_kw in ["input", "execute", "query", "run"]):
                if "sprintf" in calls or "strcpy" in calls:
                    cwe_labels.append("CWE-89")
                    vulnerability_score += 0.8
        
        # CWE-22: Path Traversal
        if any(path_kw in func_name for path_kw in ["path", "file", "open", "read", "write"]):
            if "strcpy" in calls or "sprintf" in calls:
                if any(unsafe in strings for unsafe in ["../", "..\\", "/", "\\"]):
                    cwe_labels.append("CWE-22")
                    vulnerability_score += 0.6
        
        # CWE-78: Command Injection
        if any(cmd_kw in func_name for cmd_kw in ["command", "exec", "system", "shell", "run"]):
            if "sprintf" in calls or "system" in calls:
                cwe_labels.append("CWE-78")
                vulnerability_score += 0.8
        
        # CWE-311: Missing Encryption
        if any(crypto_kw in func_name for crypto_kw in ["password", "secret", "key", "token", "auth"]):
            if not any(enc in calls for enc in ["encrypt", "aes", "sha", "md5", "crypto"]):
                if "strcpy" in calls or "memcpy" in calls:  # Plaintext handling
                    cwe_labels.append("CWE-311")
                    vulnerability_score += 0.5
        
        # CWE-327: Use of Broken Crypto
        if any(crypto in calls for crypto in ["md5", "des", "rc4"]):
            # Weak cryptographic algorithms
            cwe_labels.append("CWE-327")
            vulnerability_score += 0.4
        
        # CWE-798: Hard-coded Credentials
        if any(cred_kw in func_name for cred_kw in ["password", "secret", "key", "token"]):
            if any(hardcode in strings for hardcode in ["password", "admin", "1234", "default"]):
                cwe_labels.append("CWE-798")
                vulnerability_score += 0.9
        
        # Additional heuristics based on complexity and patterns
        # High complexity + dangerous operations = higher risk
        complexity_score = (instructions / 100.0) + (entropy / 8.0)
        if complexity_score > 1.5 and vulnerability_score > 0.3:
            # Add CWE-120 if not already present and high risk
            if "CWE-120" not in cwe_labels and any(dc in calls for dc in ["strcpy", "sprintf", "memcpy"]):
                cwe_labels.append("CWE-120")
        
        # Remove duplicates and return
        return sorted(list(set(cwe_labels)))
    
    def _call_llm_api(self, prompt: str) -> str:
        """
        Call LLM API to get CWE labels.
        
        Returns:
            JSON string with CWE labels
        """
        if self.provider == "openai":
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.api_key)
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert analyzing firmware code for CWE vulnerabilities. Return only a JSON array of CWE IDs."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature,
                    max_tokens=500
                )
                return response.choices[0].message.content
            except ImportError:
                raise ImportError("OpenAI library not installed. Install with: pip install openai")
            except Exception as e:
                raise Exception(f"OpenAI API error: {e}")
        
        elif self.provider == "anthropic":
            try:
                from anthropic import Anthropic
                client = Anthropic(api_key=self.api_key)
                response = client.messages.create(
                    model=self.model,
                    max_tokens=500,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            except ImportError:
                raise ImportError("Anthropic library not installed. Install with: pip install anthropic")
            except Exception as e:
                raise Exception(f"Anthropic API error: {e}")
        
        elif self.provider == "ollama":
            # Ollama - Tamamen ücretsiz, local çalışır
            try:
                import requests
                response = requests.post(
                    f"{self.ollama_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security expert analyzing firmware code for CWE vulnerabilities. Return only a JSON array of CWE IDs."
                            },
                            {"role": "user", "content": prompt}
                        ],
                        "options": {
                            "temperature": self.temperature
                        },
                        "stream": False  # Non-streaming mode
                    },
                    timeout=120
                )
                response.raise_for_status()
                result = response.json()
                # Ollama returns {"message": {"content": "..."}, ...}
                if "message" in result and "content" in result["message"]:
                    return result["message"]["content"]
                else:
                    # Fallback: try to get content directly
                    return str(result.get("message", result))
            except ImportError:
                raise ImportError("Requests library not installed. Install with: pip install requests")
            except requests.exceptions.ConnectionError:
                raise Exception(f"Ollama connection error. Make sure Ollama is running: ollama serve")
            except Exception as e:
                raise Exception(f"Ollama API error: {e}")
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}. Supported: openai, anthropic, ollama")
    
    def _build_prompt(self, func_info: Dict[str, Any]) -> str:
        """Build prompt for LLM to analyze function"""
        func_name = func_info.get("name", "unknown")
        calls = func_info.get("calls", [])
        strings = func_info.get("strings", [])
        
        prompt = f"""Analyze the following firmware function and identify potential CWE vulnerabilities.

Function Name: {func_name}
Function Calls: {', '.join(calls)}
Strings: {', '.join(strings)}

CWE Categories to consider: {', '.join(self.cwe_categories)}

Return a JSON array of CWE IDs that apply to this function, or an empty array if none apply.
Format: ["CWE-XXX", "CWE-YYY"]
"""
        return prompt

