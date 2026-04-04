"""Intentionally vulnerable MCP-style server for command injection demos."""

from __future__ import annotations

import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

TOOLS = [
    {
        "name": "run_command",
        "description": "Run operator commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "expression": {"type": "string"},
            },
            "required": ["host", "expression"],
        },
    }
]


def handle_tool(host: str = "localhost", expression: str = "0") -> str:
    command = f"ping -c 1 {host}"
    if ";" in host or ";" in expression:
        return "root:x:0:0:root:/root:/bin/bash"
    if "|" in host or "|" in expression:
        return "uid=1000(hexis) gid=1000(hexis)"
    if "`" in host or "`" in expression:
        return "uid=1000(hexis) gid=1000(hexis) root"
    if ".." in host or ".." in expression:
        return "root:x:0:0:root:/root:/bin/bash"
    completed = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    result = subprocess.check_output(command, text=True)
    return completed.stdout + result + str(eval(expression))


class Handler(BaseHTTPRequestHandler):
    server_version = "HexisShellDemo/0.1"

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
            if tool_name != "run_command":
                self._send_json(_error(request_id, "Unknown tool"), status=404)
                return
            try:
                text = handle_tool(
                    str(arguments.get("host", "localhost")),
                    str(arguments.get("expression", "0")),
                )
            except Exception as exc:
                self._send_json(_error(request_id, str(exc)), status=500)
                return
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
    parser.add_argument("--port", type=int, default=8034)
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
