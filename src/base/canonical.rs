//! RFC 8785 (JCS) canonical JSON serialization for hashing.
//!
//! Values are serialized to `serde_json::Value` and then emitted in JSON
//! Canonicalization Scheme form: object members sorted by the UTF-16 code
//! units of their names, no whitespace, minimal JCS string escaping, and
//! ECMAScript number formatting (via `ryu-js`). An independent JCS
//! implementation in any language computes byte-identical output - and
//! therefore identical record ids - from the same data.
//!
//! Conformance limits (both are errors, never silent precision loss):
//! - Integers must stay within the I-JSON safe range (|n| ≤ 2^53 − 1),
//!   because JCS numbers are IEEE-754 doubles.
//! - Non-finite floats cannot occur in `serde_json::Value` and are rejected
//!   defensively.

/// Serialize maps whose keys are not strings (tuple or hash keys) as a
/// sequence of `[key, value]` pairs. JSON object keys must be strings, so
/// such maps cannot serialize as objects; a sorted pair sequence is valid
/// JSON (and JCS) and stays deterministic through `BTreeMap` ordering.
pub(crate) mod map_as_pairs {
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::marker::PhantomData;

    pub fn serialize<K, V, S>(map: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        K: Serialize,
        V: Serialize,
        S: Serializer,
    {
        serializer.collect_seq(map.iter())
    }

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: serde::Deserialize<'de> + Ord,
        V: serde::Deserialize<'de>,
        D: Deserializer<'de>,
    {
        struct PairMapVisitor<K, V>(PhantomData<(K, V)>);

        impl<'de, K, V> Visitor<'de> for PairMapVisitor<K, V>
        where
            K: serde::Deserialize<'de> + Ord,
            V: serde::Deserialize<'de>,
        {
            type Value = BTreeMap<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence of unique [key, value] pairs")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = seq.next_element::<(K, V)>()? {
                    if map.insert(key, value).is_some() {
                        return Err(A::Error::custom("duplicate key in pair-encoded map"));
                    }
                }
                Ok(map)
            }
        }

        deserializer.deserialize_seq(PairMapVisitor(PhantomData))
    }
}

/// Serialize ordinary JSON maps normally while rejecting duplicate keys on
/// decode. Serde's default `BTreeMap` decoder is last-value-wins, which would
/// make normative rule documents ambiguous across implementations.
pub(crate) mod strict_map {
    use serde::de::{Error as _, MapAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::marker::PhantomData;

    pub fn serialize<K, V, S>(map: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        K: Serialize + Ord,
        V: Serialize,
        S: Serializer,
    {
        map.serialize(serializer)
    }

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: serde::Deserialize<'de> + Ord,
        V: serde::Deserialize<'de>,
        D: Deserializer<'de>,
    {
        struct StrictMapVisitor<K, V>(PhantomData<(K, V)>);

        impl<'de, K, V> Visitor<'de> for StrictMapVisitor<K, V>
        where
            K: serde::Deserialize<'de> + Ord,
            V: serde::Deserialize<'de>,
        {
            type Value = BTreeMap<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique keys")
            }

            fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = entries.next_entry::<K, V>()? {
                    if map.insert(key, value).is_some() {
                        return Err(A::Error::custom("duplicate map key"));
                    }
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(StrictMapVisitor(PhantomData))
    }
}

/// Serialize sets as before while rejecting duplicate members on decode.
pub(crate) mod strict_set {
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::collections::BTreeSet;
    use std::fmt;
    use std::marker::PhantomData;

    pub fn serialize<T, S>(set: &BTreeSet<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize + Ord,
        S: Serializer,
    {
        set.serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<BTreeSet<T>, D::Error>
    where
        T: serde::Deserialize<'de> + Ord,
        D: Deserializer<'de>,
    {
        struct StrictSetVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for StrictSetVisitor<T>
        where
            T: serde::Deserialize<'de> + Ord,
        {
            type Value = BTreeSet<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence with unique members")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut set = BTreeSet::new();
                while let Some(value) = seq.next_element::<T>()? {
                    if !set.insert(value) {
                        return Err(A::Error::custom("duplicate set member"));
                    }
                }
                Ok(set)
            }
        }

        deserializer.deserialize_seq(StrictSetVisitor(PhantomData))
    }
}

use serde::ser::Error as _;
use serde::Serialize;
use serde_json::{Map, Number, Value};

/// Largest integer magnitude exactly representable as an IEEE-754 double
/// (2^53 − 1); the I-JSON safe range JCS numbers must stay within.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Serialize a value to RFC 8785 (JCS) canonical JSON bytes.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_jcs(&v, &mut out)?;
    Ok(out)
}

/// Serialize a value to an RFC 8785 (JCS) canonical JSON string.
pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = canonical_json(value)?;
    // canonical_json only emits valid UTF-8 (JSON escapes + literal
    // UTF-8), so this cannot fail in practice - but the library's no-panic
    // contract holds literally: propagate instead of expect.
    String::from_utf8(bytes)
        .map_err(|e| serde_json::Error::custom(format!("JCS output was not UTF-8: {e}")))
}

fn write_jcs(value: &Value, out: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_jcs(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    // JCS sorts members by the UTF-16 code units of the (unescaped) name,
    // which differs from UTF-8 byte order when BMP characters in
    // U+E000..U+FFFF meet supplementary-plane characters.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));

    out.push(b'{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_string(key, out);
        out.push(b':');
        // The key came from this map; get() keeps the path panic-free by
        // construction rather than by argument.
        let value = map
            .get(key.as_str())
            .ok_or_else(|| serde_json::Error::custom("map key vanished during iteration"))?;
        write_jcs(value, out)?;
    }
    out.push(b'}');
    Ok(())
}

fn write_number(n: &Number, out: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(serde_json::Error::custom(format!(
                "integer {u} exceeds the I-JSON safe range required by JCS"
            )));
        }
        out.extend_from_slice(u.to_string().as_bytes());
    } else if let Some(i) = n.as_i64() {
        if i < -(MAX_SAFE_INTEGER as i64) {
            return Err(serde_json::Error::custom(format!(
                "integer {i} exceeds the I-JSON safe range required by JCS"
            )));
        }
        out.extend_from_slice(i.to_string().as_bytes());
    } else if let Some(f) = n.as_f64() {
        if !f.is_finite() {
            return Err(serde_json::Error::custom("non-finite number in JCS input"));
        }
        let mut buf = ryu_js::Buffer::new();
        out.extend_from_slice(buf.format_finite(f).as_bytes());
    } else {
        return Err(serde_json::Error::custom("unrepresentable JSON number"));
    }
    Ok(())
}

/// JCS string escaping: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`,
/// `\u00xx` (lowercase hex) for remaining control characters, everything
/// else as literal UTF-8.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn jcs_str(v: &Value) -> String {
        canonical_json_string(v).unwrap()
    }

    #[test]
    fn test_canonical_determinism() {
        let mut map = BTreeMap::new();
        map.insert("z", 1);
        map.insert("a", 2);
        let bytes1 = canonical_json(&map).unwrap();
        let bytes2 = canonical_json(&map).unwrap();
        assert_eq!(bytes1, bytes2);
        // Keys must be sorted
        let s = String::from_utf8(bytes1).unwrap();
        assert_eq!(s, r#"{"a":2,"z":1}"#);
    }

    /// The complete input/output example from RFC 8785 §3.3. The input
    /// literals deliberately carry the RFC's excessive precision.
    #[test]
    #[allow(clippy::excessive_precision)]
    fn test_rfc8785_example() {
        let input = json!({
            "numbers": [333333333.33333329f64, 1E30f64, 4.50f64, 2e-3f64,
                        0.000000000000000000000000001f64],
            "string": "\u{20ac}$\u{000F}\u{000a}A'B\"\\\\\"/",
            "literals": [null, true, false]
        });
        let expected = "{\"literals\":[null,true,false],\
             \"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\
             \"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
        assert_eq!(jcs_str(&input), expected);
    }

    /// ECMAScript number serialization cases from RFC 8785 Appendix B
    /// (representable subset) plus integer boundaries.
    #[test]
    fn test_rfc8785_numbers() {
        for (input, expected) in [
            (0.0f64, "0"),
            (-0.0f64, "0"),
            (1.0, "1"),
            (-1.0, "-1"),
            (0.5, "0.5"),
            (1e+21, "1e+21"),
            (1e+20, "100000000000000000000"),
            (5e-324, "5e-324"),
            (9007199254740994.0, "9007199254740994"),
            (999999999999999700000.0, "999999999999999700000"),
            (0.000001, "0.000001"),
            (0.0000001, "1e-7"),
        ] {
            assert_eq!(jcs_str(&json!(input)), expected, "for {input}");
        }
        assert_eq!(jcs_str(&json!(9007199254740991u64)), "9007199254740991");
        assert_eq!(jcs_str(&json!(-9007199254740991i64)), "-9007199254740991");
    }

    /// Integers outside the I-JSON safe range are an error, not silent
    /// precision loss.
    #[test]
    fn test_unsafe_integer_rejected() {
        assert!(canonical_json(&json!(9007199254740992u64)).is_err());
        assert!(canonical_json(&json!(u64::MAX)).is_err());
        assert!(canonical_json(&json!(-9007199254740992i64)).is_err());
    }

    /// Property names sort by UTF-16 code units, not UTF-8 bytes: a
    /// supplementary-plane character (here U+1D306, UTF-16 D834 DF06)
    /// sorts before U+E000 in UTF-16 but after it in UTF-8.
    #[test]
    fn test_utf16_key_order() {
        let input = json!({
            "\u{e000}": 1,
            "\u{1d306}": 2,
        });
        assert_eq!(jcs_str(&input), "{\"\u{1d306}\":2,\"\u{e000}\":1}");
    }

    /// Control characters escape per JCS; DEL (U+007F) stays literal.
    #[test]
    fn test_string_escapes() {
        let input = json!("\u{0008}\u{0009}\u{000a}\u{000b}\u{000c}\u{000d}\u{001f}\u{007f}");
        assert_eq!(jcs_str(&input), "\"\\b\\t\\n\\u000b\\f\\r\\u001f\u{007f}\"");
    }
}
