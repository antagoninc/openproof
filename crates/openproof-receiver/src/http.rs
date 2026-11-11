//! What the role service reads from the owner's account: one bounded message
//! for each connection, and strict JSON.
use crate::Result;
use std::io::{Read, Write};

/// Read one message: a 4-byte big-endian length, then that many bytes.
pub fn read_message(stream: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max {
        return Err("message size".into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// Write one message in the same form.
pub fn write_message(stream: &mut impl Write, body: &[u8]) -> Result<()> {
    stream.write_all(&u32::try_from(body.len())?.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/// JSON with duplicate-key and float refusal, like the Python reference loader.
pub fn strict_json(bytes: &[u8]) -> Result<serde_json::Value> {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Value};
    struct Strict;
    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
            d.deserialize_any(Strict)
        }
    }
    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON without floats or duplicate keys")
        }
        fn visit_bool<E: Error>(self, v: bool) -> std::result::Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E: Error>(self, v: i64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_u64<E: Error>(self, v: u64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_f64<E: Error>(self, _: f64) -> std::result::Result<Value, E> {
            Err(E::custom("floating-point numbers are refused"))
        }
        fn visit_str<E: Error>(self, v: &str) -> std::result::Result<Value, E> {
            Ok(Value::String(v.to_string()))
        }
        fn visit_string<E: Error>(self, v: String) -> std::result::Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_unit<E: Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> std::result::Result<Value, A::Error> {
            let mut out = vec![];
            while let Some(v) = s.next_element_seed(Strict)? {
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> std::result::Result<Value, A::Error> {
            let mut out = Map::new();
            while let Some(k) = m.next_key::<String>()? {
                if out.contains_key(&k) {
                    return Err(A::Error::custom("duplicate JSON field"));
                }
                let v = m.next_value_seed(Strict)?;
                out.insert(k, v);
            }
            Ok(Value::Object(out))
        }
    }
    if bytes.len() > 1_048_576 {
        return Err("input exceeds 1 MiB".into());
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let v = Strict.deserialize(&mut d)?;
    d.end()?;
    Ok(v)
}

/// The object's fields: all of `required`, nothing outside `required` and `optional`.
pub fn fields<'a>(
    v: &'a serde_json::Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>> {
    let m = v.as_object().ok_or("object required")?;
    if !required.iter().all(|k| m.contains_key(*k))
        || !m
            .keys()
            .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
    {
        return Err("missing or unknown fields".into());
    }
    Ok(m)
}

pub fn text<'a>(m: &'a serde_json::Map<String, serde_json::Value>, k: &str) -> Result<&'a str> {
    m.get(k)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{k} must be text").into())
}

pub fn integer(m: &serde_json::Map<String, serde_json::Value>, k: &str) -> Result<u64> {
    m.get(k)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{k} must be a nonnegative integer").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_json_refuses_duplicates_and_floats() {
        assert!(strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json(br#"{"a":1.5}"#).is_err());
        assert!(strict_json(br#"{"a":[1,{"b":"x"}]} "#).is_ok());
        assert!(strict_json(br#"{"a":1} x"#).is_err());
    }
    #[test]
    fn messages_are_bounded() {
        let mut wire = vec![];
        write_message(&mut wire, b"{}").unwrap();
        assert_eq!(wire, b"\0\0\0\x02{}");
        assert_eq!(read_message(&mut &wire[..], 2).unwrap(), b"{}");
        assert!(read_message(&mut &wire[..], 1).is_err());
        for bad in [&b"\0\0\0\0"[..], b"\0\0\0\x05{}", b"\0\0"] {
            assert!(read_message(&mut &bad[..], 1024).is_err());
        }
    }
}
