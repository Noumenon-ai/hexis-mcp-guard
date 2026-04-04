"""Known MCP vulnerability patterns and CWE mappings."""

from __future__ import annotations

# Dangerous functions that indicate shell injection risk
SHELL_DANGEROUS_CALLS = {
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "os.system",
    "os.popen",
    "os.exec",
    "os.execvp",
    "os.execve",
}

EVAL_FUNCTIONS = {"eval", "exec", "compile", "execfile"}

# Patterns that indicate SSRF risk
SSRF_URL_PARAMS = {"url", "uri", "endpoint", "target", "host", "link", "href", "src", "callback"}

SSRF_FETCH_FUNCTIONS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "urllib.request.urlopen",
    "aiohttp.ClientSession",
}

# Internal/metadata IPs to flag — anchored to avoid matching version strings
INTERNAL_IP_PATTERNS = [
    r"\b169\.254\.169\.254\b",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"\b100\.100\.100\.200\b",  # Alibaba metadata
    r"\b127\.0\.0\.\d+\b",  # Loopback
    r"(?<!\d)10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)",  # Private class A
    r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b",  # Private class B
    r"\b192\.168\.\d+\.\d+\b",  # Private class C
    # 0.0.0.0 omitted — it's a bind address, not an SSRF target
]

# Prompt injection indicators
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+(instructions?|prompts?)",
    r"you\s+are\s+now\s+(?:a|an)\s+",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"IMPORTANT:\s*(?:ignore|disregard|override)",
    r"(?:do\s+not|don'?t)\s+(?:tell|reveal|show|disclose)",
    r"act\s+as\s+(?:if|though)\s+you",
    r"pretend\s+(?:you|that)\s+",
    r"new\s+instructions?:\s*",
    r"BEGIN\s+(?:NEW\s+)?INSTRUCTIONS?",
]

# Resource exposure patterns
FILESYSTEM_DANGEROUS = {
    "open(",
    "os.path.join(",
    "pathlib.Path(",
    "shutil.copy",
    "shutil.move",
    "os.listdir",
    "os.walk",
    "glob.glob",
}

SQL_INJECTION_PATTERNS = [
    r"""f['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*\{""",
    r"""\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)""",
    r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*%\s*\(""",  # % operator interpolation
    r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*\+\s*(?:user|input|param|arg|request)""",
]

# CWE mappings for each category
CWE_MAPPINGS = {
    "ssrf": "CWE-918",
    "shell_injection": "CWE-78",
    "code_injection": "CWE-95",
    "auth_missing": "CWE-306",
    "auth_bypass": "CWE-862",
    "prompt_injection": "CWE-94",
    "path_traversal": "CWE-22",
    "sql_injection": "CWE-89",
    "cleartext_transport": "CWE-319",
}

# Auth-related keywords
AUTH_KEYWORDS = {
    "authenticate",
    "authorization",
    "auth_token",
    "api_key",
    "x-api-key",
    "bearer",
    "jwt",
    "mtls",
    "session",
    "credentials",
}

# MCP transport types
MCP_TRANSPORTS = {"stdio", "sse", "streamable-http"}
