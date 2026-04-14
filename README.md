# HEXIS MCP GUARD

Security scanner for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers.

## Install

```bash
pip install hexis-mcp-guard
```

Or from source:

```bash
git clone https://github.com/hexis-security/hexis-mcp-guard.git
cd hexis-mcp-guard
pip install -e ".[dev]"
```

## Usage

```bash
hexis scan ./my-server/
hexis scan --format sarif -o results.sarif ./server/
hexis scan --format json ./server/
hexis scan --url http://localhost:8080 --dynamic
hexis scan ./server/ --ai
hexis scan ./server/ --ci --fail-on high
hexis scan ./server/ --baseline .hexis-baseline.json
hexis rules
```

## Features

- 14 security rules (SSRF, shell injection, auth, prompt injection, resource exposure, transport)
- Static analysis + dynamic probing
- SARIF 2.1.0 output for GitHub Security tab
- JSON + rich terminal output
- CI/CD ready (exit codes)
- Optional AI reasoning (Claude)

## Rules

| Rule | Severity | Category | Description |
| --- | --- | --- | --- |
| HEXIS-AUTH-001 | HIGH | auth | No authentication on transport |
| HEXIS-AUTH-002 | HIGH | auth | Missing authorization checks on sensitive tools |
| HEXIS-CMD-001 | CRITICAL | shell_injection | subprocess/exec with user input |
| HEXIS-CMD-002 | CRITICAL | shell_injection | shell=True with string interpolation |
| HEXIS-CMD-003 | CRITICAL | shell_injection | eval/exec on tool arguments |
| HEXIS-PI-001 | HIGH | prompt_injection | Tool description contains injection patterns |
| HEXIS-PI-002 | MEDIUM | prompt_injection | Return values flow unsanitized to LLM context |
| HEXIS-PI-003 | HIGH | prompt_injection | Tool poisoning via hidden instructions in descriptions |
| HEXIS-RES-001 | HIGH | resource_exposure | Unrestricted file system access |
| HEXIS-RES-002 | HIGH | resource_exposure | SQL query tool without parameterization |
| HEXIS-SSRF-001 | HIGH | ssrf | URL parameter in tool inputSchema without validation |
| HEXIS-SSRF-002 | CRITICAL | ssrf | Server-side fetch with user-controlled URL |
| HEXIS-SSRF-003 | CRITICAL | ssrf | Internal IP/metadata endpoint accessible |
| HEXIS-TLS-001 | MEDIUM | transport | Plaintext HTTP transport in production |

## CI/CD Integration

### GitHub Actions

```yaml
- name: MCP Security Scan
  run: |
    pip install hexis-mcp-guard
    hexis scan ./src --format sarif --output results.sarif --ci --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | No HIGH/CRITICAL findings |
| 1 | HIGH findings detected |
| 2 | CRITICAL findings detected |

## License

MIT
---
Built by [Noumenon](https://github.com/Noumenon-ai)