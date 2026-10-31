"""HTTP reverse proxy with method-level MCP tool authorization."""

from __future__ import annotations

import base64
import binascii
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_DOWNSTREAM_URL = "http://127.0.0.1:8001"
DEFAULT_MAX_REQUEST_BYTES = 1_048_576
DEFAULT_DOWNSTREAM_TIMEOUT_SECONDS = 10
JSON_CONTENT_TYPES = {"application/json", "application/json-rpc"}


class RequestTooLargeError(ValueError):
    """Raised when an incoming JSON-RPC body exceeds the configured limit."""


def configured_positive_number(
    environment_name: str, default: int | float
) -> int | float:
    # Reject invalid or non-positive operational limits before serving requests.
    raw_value = os.environ.get(environment_name, str(default))
    try:
        value = float(raw_value)
    except ValueError as error:
        raise ValueError(f"{environment_name} must be a positive number") from error
    if value <= 0:
        raise ValueError(f"{environment_name} must be a positive number")
    return int(value) if value.is_integer() else value


def role_from_authorization(value: str | None) -> str | None:
    # Treat the HTTP auth scheme as case-insensitive while failing closed for bad tokens.
    """Extract a role from a Bearer token or from a JWT payload."""
    if not value:
        return None

    scheme, separator, token = value.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return None
    token = token.strip()
    if not token:
        return None
    if token in {"admin", "viewer"}:
        return token

    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        )
    except (binascii.Error, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    role = payload.get("role")
    return role if isinstance(role, str) else None


def json_rpc_error(request_id: Any, code: int, message: str) -> bytes:
    # Keep gateway-generated failures in the JSON-RPC response format.
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    ).encode("utf-8")


def is_authorized_tool_call(
    payload: dict[str, Any], authorization: str | None
) -> bool:
    # Only admin-prefixed tools require an admin role; all other MCP methods pass through.
    if payload.get("method") != "tools/call":
        return True

    params = payload.get("params")
    if not isinstance(params, dict):
        return True

    tool_name = params.get("name")
    if not isinstance(tool_name, str) or not tool_name.startswith("admin_"):
        return True

    return role_from_authorization(authorization) == "admin"


def validate_json_rpc(payload: Any) -> tuple[bool, Any]:
    # Validate the envelope before accessing request fields or applying policy.
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        request_id = payload.get("id") if isinstance(payload, dict) else None
        return False, request_id
    return True, payload.get("id")


def is_json_content_type(value: str | None) -> bool:
    # Accept JSON media types with optional parameters such as a charset.
    if not value:
        return False
    return value.split(";", 1)[0].strip().lower() in JSON_CONTENT_TYPES


class GatewayHandler(BaseHTTPRequestHandler):
    downstream_url = os.environ.get("DOWNSTREAM_URL", DEFAULT_DOWNSTREAM_URL).rstrip("/")
    max_request_bytes = int(
        configured_positive_number("MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES)
    )
    downstream_timeout_seconds = float(
        configured_positive_number(
            "DOWNSTREAM_TIMEOUT_SECONDS", DEFAULT_DOWNSTREAM_TIMEOUT_SECONDS
        )
    )

    def do_POST(self) -> None:
        # Validate the request before applying tool-level authorization.
        if not is_json_content_type(self.headers.get("Content-Type")):
            self._send_json(json_rpc_error(None, -32600, "JSON content type required"), 415)
            return
        try:
            payload = self._read_payload()
        except RequestTooLargeError:
            self._send_json(json_rpc_error(None, -32600, "Request too large"), 413)
            return
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self._send_json(json_rpc_error(None, -32700, "Parse error"), 400)
            return

        valid, request_id = validate_json_rpc(payload)
        if not valid:
            self._send_json(json_rpc_error(request_id, -32600, "Invalid Request"), 400)
            return

        if not is_authorized_tool_call(payload, self.headers.get("Authorization")):
            self._send_json(
                json_rpc_error(request_id, -32001, "Unauthorized Tool Call"), 403
            )
            return

        self._forward(payload)

    def do_GET(self) -> None:
        # MCP JSON-RPC requests are POST-only; make the protocol failure explicit.
        self._method_not_allowed()

    def do_PUT(self) -> None:
        # Do not allow unrelated HTTP methods to reach the downstream server.
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        # Do not allow unrelated HTTP methods to reach the downstream server.
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        # Do not allow unrelated HTTP methods to reach the downstream server.
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        # Return a JSON-RPC-shaped error so clients receive a consistent body.
        self._send_json(json_rpc_error(None, -32600, "POST required"), 405)

    def _read_payload(self) -> Any:
        # Reject oversized bodies before reading them into memory.
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            raise ValueError("Content-Length header is required")
        try:
            length = int(content_length)
        except ValueError as error:
            raise ValueError("Content-Length must be an integer") from error
        if length < 0 or length > self.max_request_bytes:
            raise RequestTooLargeError("Request body exceeds configured limit")
        return json.loads(self.rfile.read(length))

    def _forward(self, payload: dict[str, Any]) -> None:
        # Preserve the request path and authorization context for the downstream server.
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        authorization = self.headers.get("Authorization")
        if authorization:
            headers["Authorization"] = authorization
        request = Request(
            self.downstream_url + self.path,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.downstream_timeout_seconds) as response:
                response_body = response.read()
                status = response.status
                content_type = response.headers.get("Content-Type", "application/json")
        except HTTPError as error:
            try:
                response_body = error.read()
                status = error.code
                content_type = error.headers.get("Content-Type", "application/json")
            finally:
                error.close()
        except (TimeoutError, URLError):
            self._send_json(
                json_rpc_error(payload.get("id"), -32603, "Downstream server unavailable"), 502
            )
            return

        self.send_response(status)
        self.send_header("X-Request-ID", str(payload.get("id", "")))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response_body)

    def _send_json(self, body: bytes, status: int) -> None:
        # Send locally handled errors with explicit response metadata.
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Allow", "POST")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Avoid logging request data, which may contain sensitive tool arguments.
        return


def main() -> None:
    # Configure the listener through environment variables for local deployment.
    host = os.environ.get("GATEWAY_HOST", "127.0.0.1")
    port = int(os.environ.get("GATEWAY_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), GatewayHandler)
    # Stop accepting new work on termination signals and let active requests finish.
    def shutdown_handler(signum: int, frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown_handler)
    print(f"MCP gateway listening on http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
