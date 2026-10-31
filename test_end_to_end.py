import json
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from gateway import GatewayHandler
from mock_mcp_server import MockMcpHandler


class RecordingMockHandler(MockMcpHandler):
    """Track requests that pass the gateway during end-to-end tests."""

    requests = []

    def do_POST(self):
        # Record the downstream payload before using the normal mock response behavior.
        length = int(self.headers.get("Content-Length", "0"))
        self.requests.append(json.loads(self.rfile.read(length)))
        self._request_body = self.requests[-1]
        self._replay_request()

    def _replay_request(self):
        # Reconstruct the request stream expected by the inherited handler.
        payload = self._request_body
        method = payload.get("method")
        request_id = payload.get("id")
        if method == "tools/list":
            result = {
                "tools": [
                    {"name": "read_status"},
                    {"name": "admin_reset_key"},
                ]
            }
        else:
            params = payload.get("params", {})
            result = {
                "content": [
                    {"type": "text", "text": f"Called {params.get('name')}"}
                ]
            }
        self._send_json({"jsonrpc": "2.0", "id": request_id, "result": result}, 200)


class EndToEndGatewayTests(unittest.TestCase):
    """Exercise the gateway and downstream mock as one running system."""

    @classmethod
    def setUpClass(cls):
        # Start an isolated downstream server and point the gateway at its ephemeral port.
        RecordingMockHandler.requests = []
        cls.downstream = ThreadingHTTPServer(("127.0.0.1", 0), RecordingMockHandler)
        cls.downstream_thread = threading.Thread(
            target=cls.downstream.serve_forever, daemon=True
        )
        cls.downstream_thread.start()
        GatewayHandler.downstream_url = (
            f"http://127.0.0.1:{cls.downstream.server_port}"
        )
        cls.gateway = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
        cls.gateway_thread = threading.Thread(
            target=cls.gateway.serve_forever, daemon=True
        )
        cls.gateway_thread.start()

    @classmethod
    def tearDownClass(cls):
        # Shut down both servers so the integration suite leaves no listeners behind.
        cls.gateway.shutdown()
        cls.gateway.server_close()
        cls.downstream.shutdown()
        cls.downstream.server_close()
        cls.gateway_thread.join(timeout=2)
        cls.downstream_thread.join(timeout=2)

    def request(self, payload, token=None):
        # Send a JSON-RPC request through the complete gateway path.
        connection = HTTPConnection("127.0.0.1", self.gateway.server_port)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        connection.request("POST", "/mcp", json.dumps(payload), headers)
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        return response.status, body

    def test_tools_list_reaches_downstream_transparently(self):
        # Public tool discovery should be forwarded and return the downstream result.
        status, response = self.request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["tools"][0]["name"], "read_status")
        self.assertEqual(RecordingMockHandler.requests[-1]["method"], "tools/list")

    def test_viewer_admin_call_is_blocked_before_downstream(self):
        # Unauthorized admin calls must not appear in the downstream request log.
        before = len(RecordingMockHandler.requests)
        status, response = self.request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "admin_reset_key"},
            },
            "viewer",
        )
        self.assertEqual(status, 403)
        self.assertEqual(response["error"]["code"], -32001)
        self.assertEqual(len(RecordingMockHandler.requests), before)

    def test_admin_call_reaches_downstream(self):
        # An admin role should pass the gateway policy and invoke the downstream tool.
        status, response = self.request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "admin_reset_key"},
            },
            "admin",
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["content"][0]["text"], "Called admin_reset_key")
        self.assertEqual(RecordingMockHandler.requests[-1]["method"], "tools/call")


if __name__ == "__main__":
    unittest.main()
