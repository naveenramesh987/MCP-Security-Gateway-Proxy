import json
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from mock_mcp_server import MockMcpHandler


class MockMcpServerTests(unittest.TestCase):
    """Verify the deterministic downstream server used by local demonstrations."""

    @classmethod
    def setUpClass(cls):
        # Use an ephemeral port so tests do not depend on local service state.
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockMcpHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        # Stop the server and close its listening socket after all requests finish.
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, payload):
        # Send one JSON-RPC request to the mock server and decode its response.
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        body = json.dumps(payload)
        connection.request(
            "POST",
            "/mcp",
            body,
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response_body = json.loads(response.read())
        connection.close()
        return response.status, response_body

    def test_tools_list_returns_available_tools(self):
        # The mock advertises both public and protected tools.
        status, response = self.request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [tool["name"] for tool in response["result"]["tools"]],
            ["read_status", "admin_reset_key"],
        )

    def test_tools_call_returns_tool_result(self):
        # The mock returns a deterministic result for forwarded tool calls.
        status, response = self.request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_status"},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["content"][0]["text"], "Called read_status")

    def test_unknown_method_returns_method_error(self):
        # Unsupported downstream methods produce a JSON-RPC method-not-found error.
        status, response = self.request(
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list"}
        )
        self.assertEqual(status, 404)
        self.assertEqual(response["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
