import base64
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection

from gateway import (
    GatewayHandler,
    configured_positive_number,
    is_authorized_tool_call,
    role_from_authorization,
    validate_json_rpc,
)


class DownstreamHandler(BaseHTTPRequestHandler):
    requests = []
    authorization_headers = []
    fail_requests = False

    def do_POST(self):
        # Record forwarded calls so authorization tests can verify proxy behavior.
        length = int(self.headers["Content-Length"])
        self.requests.append(json.loads(self.rfile.read(length)))
        self.authorization_headers.append(self.headers.get("Authorization"))
        if self.fail_requests:
            body = b'{"error":"downstream failure"}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"jsonrpc": "2.0", "id": self.requests[-1]["id"], "result": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Keep test output focused on assertion results.
        return


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Run an isolated downstream server and gateway on ephemeral ports.
        DownstreamHandler.requests = []
        DownstreamHandler.authorization_headers = []
        DownstreamHandler.fail_requests = False
        cls.downstream = ThreadingHTTPServer(("127.0.0.1", 0), DownstreamHandler)
        cls.downstream_thread = threading.Thread(target=cls.downstream.serve_forever, daemon=True)
        cls.downstream_thread.start()
        GatewayHandler.downstream_url = f"http://127.0.0.1:{cls.downstream.server_port}"
        cls.gateway = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
        cls.gateway_thread = threading.Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.gateway_thread.start()

    @classmethod
    def tearDownClass(cls):
        # Release both test servers after the suite completes.
        cls.gateway.shutdown()
        cls.downstream.shutdown()

    def call(self, payload, token=None):
        # Send one JSON-RPC request through the gateway under test.
        connection = HTTPConnection("127.0.0.1", self.gateway.server_port)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        connection.request("POST", "/mcp", json.dumps(payload), headers)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response.status, json.loads(body)

    def call_with_content_type(self, payload, content_type):
        # Send a valid JSON payload with a caller-selected media type.
        connection = HTTPConnection("127.0.0.1", self.gateway.server_port)
        body = json.dumps(payload)
        connection.request("POST", "/mcp", body, {"Content-Type": content_type})
        response = connection.getresponse()
        response_body = json.loads(response.read())
        connection.close()
        return response.status, response_body, response.getheader("X-Request-ID")

    def call_raw(self, body):
        # Send raw data to exercise the gateway's JSON parsing error path.
        connection = HTTPConnection("127.0.0.1", self.gateway.server_port)
        connection.request(
            "POST",
            "/mcp",
            body,
            {"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response.status, json.loads(body)

    def test_tools_list_is_forwarded(self):
        # tools/list should pass through without tool authorization.
        status, response = self.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(status, 200)
        self.assertEqual(response["id"], 1)

    def test_json_content_type_parameters_are_accepted(self):
        # Standard JSON parameters such as charset must not block valid MCP calls.
        status, response, request_id = self.call_with_content_type(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/list"},
            "application/json; charset=utf-8",
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["id"], 9)
        self.assertEqual(request_id, "9")

    def test_non_json_content_type_is_rejected(self):
        # Non-JSON bodies must be rejected before parsing or forwarding.
        before = len(DownstreamHandler.requests)
        status, response, _ = self.call_with_content_type(
            {"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
            "text/plain",
        )
        self.assertEqual(status, 415)
        self.assertEqual(response["error"]["code"], -32600)
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_admin_tool_requires_admin_role(self):
        # Viewer tokens cannot invoke protected admin-prefixed tools.
        before = len(DownstreamHandler.requests)
        status, response = self.call(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "admin_reset_key"}},
            "viewer",
        )
        self.assertEqual(status, 403)
        self.assertEqual(response["error"]["code"], -32001)
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_admin_tool_requires_credentials(self):
        # Protected tools must reject requests that do not provide a bearer token.
        before = len(DownstreamHandler.requests)
        status, response = self.call(
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "admin_reset_key"}}
        )
        self.assertEqual(status, 403)
        self.assertEqual(response["error"]["code"], -32001)
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_admin_tool_is_forwarded_for_admin(self):
        # Admin tokens can invoke protected tools and reach the downstream server.
        status, response = self.call(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "admin_reset_key"}},
            "admin",
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["id"], 3)

    def test_non_admin_tool_is_forwarded(self):
        # Non-admin tools remain available to viewer tokens.
        status, response = self.call(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_status"}},
            "viewer",
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["id"], 4)

    def test_invalid_json_returns_parse_error(self):
        # Malformed request bodies must not reach the downstream server.
        before = len(DownstreamHandler.requests)
        status, response = self.call_raw("{not-json")
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], -32700)
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_invalid_content_length_returns_parse_error(self):
        # Invalid body metadata must be rejected before attempting JSON decoding.
        connection = HTTPConnection("127.0.0.1", self.gateway.server_port)
        connection.putrequest("POST", "/mcp")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "not-an-integer")
        connection.endheaders()
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 400)
        self.assertEqual(body["error"]["code"], -32700)

    def test_jwt_admin_role_is_accepted(self):
        # JWT role claims should authorize protected tools like simple role tokens.
        payload = base64.urlsafe_b64encode(b'{"role":"admin"}').decode().rstrip("=")
        token = f"header.{payload}.signature"
        self.assertEqual(role_from_authorization(f"Bearer {token}"), "admin")

    def test_malformed_jwt_has_no_role(self):
        # Invalid JWT payloads must fail closed instead of granting access.
        self.assertIsNone(role_from_authorization("Bearer header.not-base64.signature"))
        self.assertIsNone(role_from_authorization("Basic admin"))
        self.assertIsNone(role_from_authorization("Bearer header.%%%.signature"))
        self.assertIsNone(role_from_authorization("Bearer"))
        self.assertIsNone(role_from_authorization("Bearer   "))

    def test_bearer_scheme_is_case_insensitive(self):
        # HTTP authentication schemes are case-insensitive.
        self.assertEqual(role_from_authorization("bearer admin"), "admin")
        self.assertEqual(role_from_authorization("BEARER viewer"), "viewer")

    def test_authorization_policy_only_protects_admin_tools(self):
        # The policy helper should allow public tools and reject protected tools.
        protected = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "admin_rotate"}}
        public = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_status"}}
        self.assertFalse(is_authorized_tool_call(protected, "Bearer viewer"))
        self.assertTrue(is_authorized_tool_call(protected, "Bearer admin"))
        self.assertTrue(is_authorized_tool_call(public, "Bearer viewer"))

    def test_json_rpc_validation_returns_request_id(self):
        # Invalid envelopes retain their id so clients can correlate the error.
        valid, request_id = validate_json_rpc({"jsonrpc": "1.0", "id": "request-1"})
        self.assertFalse(valid)
        self.assertEqual(request_id, "request-1")

    def test_positive_configuration_values_are_parsed(self):
        # Operational limits accept numeric strings and preserve integer values.
        self.assertEqual(configured_positive_number("UNSET_TEST_VALUE", 12), 12)
        self.assertEqual(configured_positive_number("UNSET_TEST_VALUE", 1.5), 1.5)

    def test_invalid_configuration_values_are_rejected(self):
        # Invalid operational limits must fail during configuration instead of at runtime.
        original = os.environ.get("INVALID_TEST_VALUE")
        try:
            os.environ["INVALID_TEST_VALUE"] = "0"
            with self.assertRaises(ValueError):
                configured_positive_number("INVALID_TEST_VALUE", 10)
            os.environ["INVALID_TEST_VALUE"] = "not-a-number"
            with self.assertRaises(ValueError):
                configured_positive_number("INVALID_TEST_VALUE", 10)
        finally:
            if original is None:
                os.environ.pop("INVALID_TEST_VALUE", None)
            else:
                os.environ["INVALID_TEST_VALUE"] = original

    def test_authorization_header_is_forwarded(self):
        # Forwarded requests retain the caller's authorization context.
        self.call({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}, "viewer")
        self.assertEqual(
            DownstreamHandler.authorization_headers[-1],
            "Bearer viewer",
        )

    def test_unsupported_http_method_is_rejected(self):
        # Non-POST requests must stop at the gateway and never reach downstream.
        before = len(DownstreamHandler.requests)
        connection = HTTPConnection("127.0.0.1", self.gateway.server_port)
        connection.request("GET", "/mcp")
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 405)
        self.assertEqual(body["error"]["code"], -32600)
        self.assertEqual(response.getheader("Allow"), "POST")
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_downstream_http_error_is_preserved(self):
        # Downstream HTTP failures should pass through without becoming success responses.
        DownstreamHandler.fail_requests = True
        try:
            status, response = self.call(
                {"jsonrpc": "2.0", "id": 8, "method": "tools/list"}
            )
        finally:
            DownstreamHandler.fail_requests = False
        self.assertEqual(status, 503)
        self.assertEqual(response["error"], "downstream failure")

    def test_downstream_unavailability_returns_gateway_error(self):
        # A connection failure should become an explicit gateway error response.
        original_url = GatewayHandler.downstream_url
        GatewayHandler.downstream_url = "http://127.0.0.1:1"
        try:
            status, response = self.call(
                {"jsonrpc": "2.0", "id": 11, "method": "tools/list"}
            )
        finally:
            GatewayHandler.downstream_url = original_url
        self.assertEqual(status, 502)
        self.assertEqual(response["error"]["code"], -32603)

    def test_invalid_json_rpc_envelope_is_rejected(self):
        # A JSON body without the JSON-RPC 2.0 envelope must not be proxied.
        before = len(DownstreamHandler.requests)
        status, response = self.call({"jsonrpc": "1.0", "id": 7, "method": "tools/list"})
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], -32600)
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_invalid_utf8_returns_parse_error(self):
        # Invalid UTF-8 request bytes must produce a JSON-RPC parse error.
        before = len(DownstreamHandler.requests)
        status, response = self.call_raw(b"\xff")
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], -32700)
        self.assertEqual(len(DownstreamHandler.requests), before)

    def test_oversized_body_is_rejected_before_forwarding(self):
        # Bodies above the configured limit must be rejected before proxying.
        before = len(DownstreamHandler.requests)
        original_limit = GatewayHandler.max_request_bytes
        GatewayHandler.max_request_bytes = 8
        try:
            status, response = self.call_raw('{"jsonrpc":"2.0"}')
        finally:
            GatewayHandler.max_request_bytes = original_limit
        self.assertEqual(status, 413)
        self.assertEqual(response["error"]["code"], -32600)
        self.assertEqual(len(DownstreamHandler.requests), before)


if __name__ == "__main__":
    unittest.main()
