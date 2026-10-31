"""Small downstream MCP server used for local gateway demonstrations."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class MockMcpHandler(BaseHTTPRequestHandler):
    """Return deterministic JSON-RPC responses for the gateway's supported methods."""

    def do_POST(self) -> None:
        # Parse one JSON-RPC request and dispatch it to the mock tool service.
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self._send_json(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                400,
            )
            return

        request_id = request.get("id") if isinstance(request, dict) else None
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32600, "message": "Invalid Request"},
                },
                400,
            )
            return

        method = request.get("method")
        if method == "tools/list":
            result: dict[str, Any] = {
                "tools": [
                    {"name": "read_status", "description": "Read service status"},
                    {"name": "admin_reset_key", "description": "Reset an API key"},
                ]
            }
        elif method == "tools/call":
            params = request.get("params")
            tool_name = params.get("name") if isinstance(params, dict) else None
            result = {"content": [{"type": "text", "text": f"Called {tool_name}"}]}
        else:
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                },
                404,
            )
            return

        self._send_json({"jsonrpc": "2.0", "id": request_id, "result": result}, 200)

    def _send_json(self, payload: dict[str, Any], status: int) -> None:
        # Use the same response framing expected by the gateway and MCP clients.
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep local demo output focused on the server startup message.
        return


def main() -> None:
    # Bind the mock server using environment variables so it matches gateway setup.
    host = os.environ.get("MOCK_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("MOCK_MCP_PORT", "8001"))
    server = ThreadingHTTPServer((host, port), MockMcpHandler)
    print(f"Mock MCP server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
