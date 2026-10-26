from __future__ import annotations

import sys
import json
from typing import Any, Dict


def handle_request(req: Dict[str, Any]) -> Dict[str, Any]:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "MockSecureMcpServer", "version": "1.0.0"},
            },
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Reads contents of a local file safely.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string", "description": "Absolute or relative file path"}},
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "write_file",
                        "description": "Writes content to a file.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"},
                            },
                            "required": ["path", "content"],
                        },
                    },
                    {
                        "name": "http_request",
                        "description": "Performs an HTTP request to an API endpoint.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "url": {"type": "string"},
                                "body": {"type": "string"},
                            },
                            "required": ["url"],
                        },
                    },
                ]
            },
        }

    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name == "read_file":
            path = args.get("path", "")
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": f"[Simulated file content of {path}]"},
            }
        elif tool_name == "write_file":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"status": "success", "bytes_written": len(args.get("content", ""))},
            }
        elif tool_name == "http_request":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"status_code": 200, "response": "OK"},
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method {tool_name} not found"},
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32600, "message": "Invalid request"},
    }


def main():
    """Stdio loop for child MCP server process."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
