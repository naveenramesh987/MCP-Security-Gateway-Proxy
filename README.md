# MCP Security Gateway Proxy

Lightweight Python HTTP/JSON-RPC reverse proxy for MCP tool filtering.

## Run

Start the included downstream mock MCP server:

```powershell
python mock_mcp_server.py
```

In a second terminal, run the gateway:

```powershell
$env:DOWNSTREAM_URL = "http://127.0.0.1:8001"
python gateway.py
```

The gateway listens on `http://127.0.0.1:8000`. Configure `GATEWAY_HOST` and
`GATEWAY_PORT` to change the bind address or port. Incoming request bodies are
limited to 1 MiB by default; set `MAX_REQUEST_BYTES` to change that limit.
Downstream calls time out after 10 seconds by default; set
`DOWNSTREAM_TIMEOUT_SECONDS` to change that timeout. Only POST requests are
accepted by the gateway.

Requests must use `application/json` or `application/json-rpc`; JSON media type
parameters such as `charset=utf-8` are supported. Bearer tokens use a
case-insensitive `Bearer` scheme and may be the literal roles `admin` or
`viewer`, or a JWT containing `{"role":"admin"}` or `{"role":"viewer"}`.
Calls to tools whose name starts with `admin_` require the admin role and
otherwise return JSON-RPC error `-32001` without reaching the downstream
server.

Example requests (use `Invoke-RestMethod` in PowerShell so JSON quoting is preserved):

```powershell
$body = @{
  jsonrpc = "2.0"
  id = 1
  method = "tools/list"
} | ConvertTo-Json -Compress

Invoke-RestMethod -Uri "http://127.0.0.1:8000/mcp" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body

$body = @{
  jsonrpc = "2.0"
  id = 2
  method = "tools/call"
  params = @{ name = "admin_reset_key" }
} | ConvertTo-Json -Compress

Invoke-RestMethod -Uri "http://127.0.0.1:8000/mcp" `
  -Method Post `
  -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer viewer" } `
  -Body $body
```

The second request returns JSON-RPC error `-32001`. Replace `viewer` with
`admin` to forward the protected call to the mock server.

Opening either endpoint in a browser sends GET, not POST. Therefore
`http://127.0.0.1:8000` returns `POST required`, while
`http://127.0.0.1:8001` returns the mock server's `501 Unsupported method`.

## Tests

```powershell
python -m unittest -v
```
