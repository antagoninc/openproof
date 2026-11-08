#!/usr/bin/env python3
"""Bounded MCP 2025-11-25 stdio adapter: propose and commit owner-approved document updates."""

import argparse, json, sys
from witness_workflow import Broker, ref

PROTOCOL = "2025-11-25"
TOOLS = [
    {
        "name": "document_propose",
        "description": "Propose an exact document update for separate owner approval. Does not execute.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document": {"type": "string"},
                "expected_version": {"type": "integer", "minimum": 0},
                "content": {"type": "string"},
            },
            "required": ["document", "expected_version", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "document_commit",
        "description": "Commit an already owner-approved proposal. No approval, keys or destination overrides are accepted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            },
            "required": ["proposal_id"],
            "additionalProperties": False,
        },
    },
]


def dispatch(broker, request, initialized):
    ref.fields(request, ["jsonrpc", "method"], ["id", "params"])
    ref.need(request["jsonrpc"] == "2.0", "JSON-RPC version")
    method = request["method"]
    params = request.get("params", {})
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "openproof-document-broker", "version": "0.7.2"},
        }
    if not initialized:
        raise ValueError("initialize first")
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        ref.fields(params, ["name", "arguments"])
        name = params["name"]
        a = params["arguments"]
        try:
            if name == "document_propose":
                ref.fields(a, ["document", "expected_version", "content"])
                result = broker.propose(**a)
            elif name == "document_commit":
                ref.fields(a, ["proposal_id"])
                result = broker.commit(a["proposal_id"])
            else:
                raise ValueError("unknown tool")
            result = dict(result)
            result.pop("evidence_directory", None)
            return {
                "content": [{"type": "text", "text": json.dumps(result)}],
                "isError": False,
            }
        except Exception as error:
            code = (
                "proposal_unavailable"
                if isinstance(error, FileNotFoundError)
                else (
                    "invalid_request"
                    if isinstance(error, (ValueError, TypeError))
                    else "operation_failed"
                )
            )
            return {"content": [{"type": "text", "text": code}], "isError": True}
    raise ValueError("unknown method")


def serve(home):
    broker = Broker(home)
    initialized = False
    while True:
        raw = sys.stdin.buffer.readline(32769)
        if not raw:
            return
        if len(raw) > 32768 or not raw.endswith(b"\n"):
            raise ValueError("message exceeds bound or missing newline")
        identity = None
        try:
            request = ref.load_bytes(raw)
            identity = request.get("id")
            if "id" not in request:
                # Notifications never trigger tools or any side effect.
                if request.get("method") == "notifications/initialized":
                    continue
                continue
            result = dispatch(broker, request, initialized)
            if request["method"] == "initialize":
                initialized = True
            response = {"jsonrpc": "2.0", "id": identity, "result": result}
        except Exception as error:
            response = {
                "jsonrpc": "2.0",
                "id": identity,
                "error": {"code": -32600, "message": "invalid_request"},
            }
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--home", required=True)
    args = p.parse_args()
    try:
        serve(args.home)
    except Exception as error:
        print("broker_start_or_protocol_failed", file=sys.stderr)
        sys.exit(1)
