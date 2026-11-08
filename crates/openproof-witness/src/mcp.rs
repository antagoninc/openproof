//! Bounded MCP 2025-11-25 stdio server for agents. Two tools: propose an
//! exact document update, and commit one the owner already approved. Agents
//! cannot approve, choose keys or paths, or reach any other command.
use crate::broker;
use crate::http::{fields, integer, strict_json, text};
use openproof_witness::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

const PROTOCOL: &str = "2025-11-25";

fn tools() -> Value {
    json!([
        {
            "name": "document_propose",
            "description": "Propose an exact document update for separate owner approval. Does not execute.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "document": {"type": "string"},
                    "expected_version": {"type": "integer", "minimum": 0},
                    "content": {"type": "string"}
                },
                "required": ["document", "expected_version", "content"],
                "additionalProperties": false
            }
        },
        {
            "name": "document_commit",
            "description": "Commit an already owner-approved proposal. No approval, keys or destination overrides are accepted.",
            "inputSchema": {
                "type": "object",
                "properties": {"proposal_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
                "required": ["proposal_id"],
                "additionalProperties": false
            }
        }
    ])
}

fn tool_result(text: String, error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": error})
}

fn call_tool(home: &Path, params: &Value) -> Result<Value> {
    let p = fields(params, &["name", "arguments"], &[])?;
    let a = &p["arguments"];
    let outcome = (|| -> std::result::Result<Value, &'static str> {
        let invalid = |_| "invalid_request";
        match text(p, "name").map_err(invalid)? {
            "document_propose" => {
                let m = fields(a, &["document", "expected_version", "content"], &[])
                    .map_err(invalid)?;
                text(m, "document").map_err(invalid)?;
                integer(m, "expected_version").map_err(invalid)?;
                text(m, "content").map_err(invalid)?;
                broker::propose(home, a).map_err(invalid)
            }
            "document_commit" => {
                let m = fields(a, &["proposal_id"], &[]).map_err(invalid)?;
                let id = text(m, "proposal_id").map_err(invalid)?;
                broker::checked(id).map_err(invalid)?;
                broker::commit(home, id, false).map_err(|e| {
                    if e.to_string().contains("not approved") {
                        "proposal_unavailable"
                    } else {
                        "operation_failed"
                    }
                })
            }
            _ => Err("invalid_request"),
        }
    })();
    Ok(match outcome {
        Ok(mut result) => {
            if let Some(m) = result.as_object_mut() {
                m.remove("evidence_directory");
            }
            tool_result(serde_json::to_string(&result)?, false)
        }
        Err(code) => tool_result(code.into(), true),
    })
}

fn dispatch(home: &Path, request: &Value, initialized: bool) -> Result<Value> {
    let r = fields(request, &["jsonrpc", "method"], &["id", "params"])?;
    if r["jsonrpc"] != "2.0" {
        return Err("JSON-RPC version".into());
    }
    let empty = json!({});
    let params = r.get("params").unwrap_or(&empty);
    match text(r, "method")? {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "openproof-document-broker", "version": env!("CARGO_PKG_VERSION")}
        })),
        _ if !initialized => Err("initialize first".into()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => call_tool(home, params),
        _ => Err("unknown method".into()),
    }
}

pub fn serve(home: &Path) -> Result<()> {
    let home = broker::private_home(home)?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout().lock();
    let mut initialized = false;
    loop {
        let mut raw = Vec::new();
        let n = std::io::Read::take(&mut input, 32_769).read_until(b'\n', &mut raw)?;
        if n == 0 {
            return Ok(());
        }
        if raw.len() > 32_768 || !raw.ends_with(b"\n") {
            return Err("message exceeds bound or missing newline".into());
        }
        let request = strict_json(&raw).ok();
        let id = request.as_ref().and_then(|r| r.get("id").cloned());
        // Notifications never trigger tools or any side effect.
        if request.as_ref().is_some_and(|r| r.is_object()) && id.is_none() {
            continue;
        }
        let response = match request.as_ref().map(|r| dispatch(&home, r, initialized)) {
            Some(Ok(result)) => {
                if request
                    .as_ref()
                    .is_some_and(|r| r["method"] == "initialize")
                {
                    initialized = true;
                }
                json!({"jsonrpc": "2.0", "id": id, "result": result})
            }
            _ => json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32600, "message": "invalid_request"}}),
        };
        writeln!(out, "{}", serde_json::to_string(&response)?)?;
        out.flush()?;
    }
}
