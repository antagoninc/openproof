//! Minimal HTTP/1.1 for the owner app: one request per connection, bounded
//! headers and body, no chunked encoding, no keep-alive. The role services do
//! not use it, and no guarantee depends on it (docs/TCB.md).
use openproof_witness::Result;
use std::io::{Read, Write};

pub struct Request {
    pub method: String,
    pub path: String,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Header value by case-insensitive name. A repeated header is refused at parse time.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one request. Refuses repeated headers, Transfer-Encoding and bodies over `max_body`.
pub fn read_request(stream: &mut impl Read, max_body: usize) -> Result<Request> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err("request headers too large".into());
        }
        if stream.read(&mut byte)? == 0 {
            return Err("connection closed".into());
        }
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head[..head.len() - 4])?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, path, version) = (first.next(), first.next(), first.next());
    let (Some(method), Some(path), Some("HTTP/1.1" | "HTTP/1.0"), None) =
        (method, path, version, first.next())
    else {
        return Err("bad request line".into());
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let (k, v) = line.split_once(':').ok_or("bad header")?;
        if k.is_empty() || k.contains(' ') {
            return Err("bad header name".into());
        }
        if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(k)) {
            return Err("repeated header".into());
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    let mut request = Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: vec![],
    };
    if request.header("Transfer-Encoding").is_some() {
        return Err("transfer encoding refused".into());
    }
    let length: usize = match request.header("Content-Length") {
        Some(v) if v.bytes().all(|b| b.is_ascii_digit()) && !v.is_empty() && v.len() < 10 => {
            v.parse()?
        }
        Some(_) => return Err("bad content length".into()),
        None => 0,
    };
    if length > max_body {
        return Err("request body too large".into());
    }
    request.body = vec![0; length];
    stream.read_exact(&mut request.body)?;
    Ok(request)
}

/// Write a complete response and close.
pub fn respond(
    stream: &mut impl Write,
    code: u16,
    kind: &str,
    extra: &[(&str, String)],
    body: &[u8],
) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_parser_bounds_and_refusals() {
        let ok = b"POST /v1/head HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let r = read_request(&mut &ok[..], 1024).unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.body.as_slice()),
            ("POST", "/v1/head", &b"{}"[..])
        );
        for bad in [
            &b"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"[..],
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: +2\r\n\r\n{}",
            b"POST / HTTP/1.1\r\nContent-Length: 2000\r\n\r\n",
            b"POST /  HTTP/1.1\r\n\r\n",
        ] {
            assert!(read_request(&mut &bad[..], 1024).is_err());
        }
    }
}
