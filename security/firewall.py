import base64
import re
import urllib.parse
from typing import List, Tuple

class PromptInjectionFirewall:
    """
    Security firewall protecting LLMs against direct and indirect prompt injection attacks.
    Sanitizes untrusted external tool outputs, decodes obfuscated (Base64/URL) payloads,
    strips invisible Unicode exploits, and wraps content in strict isolation delimiters.
    """
    # Common prompt injection and jailbreak signatures
    _injection_patterns = [
        r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|directives)",
        r"disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)",
        r"you\s+are\s+now\s+in\s+developer\s+mode",
        r"system\s+override",
        r"reveal\s+(your\s+)?(system\s+prompt|api\s+key|passwords)",
        r"<\/?system>",
        r"\[system\]",
        r"sudo\s+mode",
        r"jailbreak",
        r"bypass\s+safety",
        r"new\s+system\s+instruction",
        r"pretend\s+you\s+have\s+no\s+(rules|restrictions|filters)",
        r"DAN\s+mode",
    ]

    _b64_pattern = re.compile(r"[A-Za-z0-9+/=]{16,}")
    _invisible_chars_pattern = re.compile(r"[\u200b\u200c\u200d\ufeff\u202a-\u202e\x00]")

    def __init__(self):
        self._regexes = [re.compile(p, re.IGNORECASE) for p in self._injection_patterns]

    def _normalize_text(self, text: str) -> str:
        """Strip invisible unicode characters and URL decode obfuscated payloads."""
        # 1. URL decoding
        try:
            decoded_url = urllib.parse.unquote(text)
        except Exception:
            decoded_url = text

        # 2. Strip invisible characters
        normalized = self._invisible_chars_pattern.sub("", decoded_url)

        # 3. Collapse extra whitespace
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def _extract_and_decode_base64(self, text: str) -> List[str]:
        """Extract and decode base64 strings embedded inside untrusted payloads."""
        decoded_snippets = []
        matches = self._b64_pattern.findall(text)
        for match in matches:
            try:
                raw_bytes = base64.b64decode(match, validate=True)
                decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                if len(decoded_str) > 6 and any(c.isalpha() for c in decoded_str):
                    decoded_snippets.append(decoded_str)
            except Exception:
                continue
        return decoded_snippets

    def sanitize(self, raw_content: str, source: str = "external_tool") -> Tuple[str, bool]:
        """
        Sanitize raw untrusted input against plain and obfuscated injection attempts.
        Returns: (sanitized_content, threat_detected)
        """
        threat_detected = False
        cleaned = raw_content

        # 1. Normalize text (URL decode, strip zero-width spaces)
        normalized = self._normalize_text(raw_content)

        # 2. Extract potential embedded base64 strings
        b64_snippets = self._extract_and_decode_base64(raw_content)

        # 3. Check regexes against raw, normalized, and decoded base64 contents
        for regex in self._regexes:
            # Check raw content
            if regex.search(cleaned):
                threat_detected = True
                cleaned = regex.sub("[BLOCKED_INJECTION_PATTERN]", cleaned)

            # Check normalized content
            if not threat_detected and regex.search(normalized):
                threat_detected = True
                cleaned = "[BLOCKED_OBFUSCATED_INJECTION_PATTERN]"

            # Check decoded base64 snippets
            if not threat_detected:
                for snippet in b64_snippets:
                    if regex.search(snippet):
                        threat_detected = True
                        cleaned = "[BLOCKED_BASE64_ENCODED_INJECTION]"
                        break

        # 4. Defend against role tag escaping
        cleaned = cleaned.replace("<system>", "&lt;system&gt;").replace("</system>", "&lt;/system&gt;")
        cleaned = cleaned.replace("[SYSTEM]", "[TAG_NEUTRALIZED]")

        # 5. Wrap in unambiguous containment boundaries
        safe_wrapped = (
            f"<untrusted_external_content source=\"{source}\" threat_detected=\"{threat_detected}\">\n"
            f"{cleaned}\n"
            f"</untrusted_external_content>"
        )

        return safe_wrapped, threat_detected
