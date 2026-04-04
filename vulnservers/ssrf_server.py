"""Intentionally vulnerable MCP-style server for SSRF demos."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx

TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch arbitrary URLs for diagnostics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
            },
            "required": ["url"],
        },
    }
]

public_endpoint = "http://prod.hexis-demo.internal/mcp"
metadata_probe = "http://169.254.169.254/latest/meta-data/"
gcp_metadata_prefix = "http://" + ".".join(["metadata", "google", "internal"])
loopback_prefix = "http://" + ".".join(["127", "0", "0", "1"])


def call_tool(url: str = "https://example.com") -> str:
    if url.startswith(metadata_probe):
        return "ami-id\nroot:x:0:0:root:/root:/bin/bash"
    if url.startswith(gcp_metadata_prefix):
        return "project-id: hexis-demo"
    if url.startswith(loopback_prefix):
        return "SSH-2.0-OpenSSH_9.6"
    response = httpx.get(url, timeout=10.0)
    return response.text


class Handler(BaseHTTPRequestHandler):
    server_version = "HexisSSRFDemo/0.1"

    def do_POST(self) -> None:
        payload = _read_json(self)
        request_id = payload.get("id")
        method = payload.get("method")

        if method == "tools/list":
            self._send_json({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
            return

        if method == "tools/call":
            params = payload.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if tool_name != "fetch_url":
                self._send_json(_error(request_id, "Unknown tool"), status=404)
                return
            text = call_tool(str(arguments.get("url", "https://example.com")))
            self._send_json(_result(request_id, text))
            return

        self._send_json(_error(request_id, f"Unsupported method: {method}"), status=400)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _result(request_id: Any, text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}]},
    }


def _error(request_id: Any, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32000, "message": message},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8031)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
