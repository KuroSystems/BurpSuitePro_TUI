//! Transfer/content decoding for proxied messages.
//!
//! The proxy stores the exact bytes it saw on the wire. Everything that needs to
//! *understand* a body (detail pane, passive scanner, AI context, Decoder hand-off)
//! goes through [`decoded_body`], so a gzip/br/deflate encoded response is never
//! analysed as binary noise.
//!
//! Invariants:
//! - decoding is bounded: the output never exceeds [`MAX_DECODED_BYTES`], so a
//!   decompression bomb cannot exhaust memory;
//! - decoding never panics and never loses the raw bytes: callers keep the wire body
//!   and only use the decoded view for display and analysis;
//! - stackable encodings are unwrapped in reverse order (`gzip, br` means gzip then br).

use std::io::Read;

use bytes::Bytes;
use flate2::read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use hyper::header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderMap};
use tracing::debug;

/// Upper bound on the size of a decoded body. Compression ratios above this are
/// treated as hostile or corrupt and the raw body is kept instead.
pub const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;

/// Compression codings this module understands. Anything else is passed through.
const SUPPORTED_CODINGS: [&str; 6] = ["gzip", "x-gzip", "deflate", "br", "zstd", "identity"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStatus {
    /// No `Content-Encoding` was present; the returned body is the wire body.
    NotEncoded,
    /// All codings were decoded successfully.
    Decoded,
    /// A supported coding was present but could not be decoded; raw body returned.
    Failed,
    /// The body carries an unsupported coding; raw body returned.
    Unsupported,
    /// A coding was present but the declared encoding was absent from the body.
    /// Common on `HEAD`/`204` responses with a non-empty `Content-Encoding`.
    EmptyBody,
}

impl DecodeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotEncoded => "identity",
            Self::Decoded => "decoded",
            Self::Failed => "decode failed",
            Self::Unsupported => "unsupported coding",
            Self::EmptyBody => "empty",
        }
    }

    pub fn is_decoded(self) -> bool {
        matches!(self, Self::Decoded)
    }

    pub fn is_problem(self) -> bool {
        matches!(self, Self::Failed | Self::Unsupported)
    }
}

#[derive(Debug, Clone)]
pub struct DecodedBody {
    pub body: Bytes,
    pub status: DecodeStatus,
    /// Codings that were applied, as they appeared on the wire (outermost first).
    pub codings: Vec<String>,
}

impl DecodedBody {
    fn raw(body: &Bytes, status: DecodeStatus) -> Self {
        Self {
            body: body.clone(),
            status,
            codings: Vec::new(),
        }
    }
}

/// Decode a message body according to its headers.
///
/// Returns a clone of the input when there is nothing to do, so callers that pass
/// an unencoded body pay only a `Bytes` refcount bump.
pub fn decoded_body(headers: &HeaderMap, body: &Bytes) -> DecodedBody {
    let codings = content_codings(headers);
    if codings.is_empty() {
        return DecodedBody::raw(body, DecodeStatus::NotEncoded);
    }

    if body.is_empty() {
        return DecodedBody {
            codings,
            body: Bytes::new(),
            status: DecodeStatus::EmptyBody,
        };
    }

    let unsupported = codings
        .iter()
        .any(|coding| !SUPPORTED_CODINGS.contains(&coding.to_ascii_lowercase().as_str()));
    if unsupported {
        debug!(?codings, "body uses an unsupported content-encoding");
        return DecodedBody {
            body: body.clone(),
            status: DecodeStatus::Unsupported,
            codings,
        };
    }

    let mut current = body.clone();
    for coding in codings.iter().rev() {
        match decode_one(coding, &current) {
            Ok(next) => current = next,
            Err(error) => {
                debug!(%coding, %error, "failed to decode content-encoding");
                return DecodedBody {
                    body: body.clone(),
                    status: DecodeStatus::Failed,
                    codings,
                };
            }
        }
    }

    DecodedBody {
        body: current,
        status: DecodeStatus::Decoded,
        codings,
    }
}

/// Clone `headers` and remove coding/length headers that no longer describe the
/// body. Used before handing a decoded body to anything that will re-send it
/// (Repeater, Intruder, plugin `send_request`) so it is not double-decoded.
///
/// Framing headers (`Transfer-Encoding`) are left untouched: they describe how the
/// owner of the connection framed the message, not the payload.
pub fn headers_for_decoded_body(headers: &HeaderMap, decoded: &DecodedBody) -> HeaderMap {
    let mut out = headers.clone();
    if !decoded.is_decoded() {
        return out;
    }
    out.remove(CONTENT_ENCODING);
    out.remove(CONTENT_LENGTH);
    out
}

/// Split a `Content-Encoding` header into its individual codings.
///
/// `Content-Encoding: gzip` is one coding; `Content-Encoding: gzip, br` is two,
/// applied in that order, so the body must be un-br'd before it is un-gzipped.
pub fn content_codings(headers: &HeaderMap) -> Vec<String> {
    let mut codings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        let Ok(value) = value.to_str() else { continue };
        for coding in value.split(',') {
            let coding = coding.trim();
            if coding.is_empty() || coding.eq_ignore_ascii_case("identity") {
                continue;
            }
            codings.push(coding.to_ascii_lowercase());
        }
    }
    codings
}

fn decode_one(coding: &str, input: &Bytes) -> Result<Bytes, String> {
    match coding.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => read_bounded(MultiGzDecoder::new(input.as_ref())),
        // RFC 9110: "deflate" means zlib-wrapped deflate. Several servers send raw
        // deflate instead, so fall back once instead of failing the whole body.
        "deflate" => read_bounded(ZlibDecoder::new(input.as_ref()))
            .or_else(|_| read_bounded(DeflateDecoder::new(input.as_ref()))),
        "br" => read_bounded(brotli::Decompressor::new(input.as_ref(), 4096)),
        "zstd" => read_bounded(zstd::stream::read::Decoder::new(input.as_ref()).map_err(|error| error.to_string())?),
        other => Err(format!("unsupported content-encoding: {other}")),
    }
}

fn read_bounded<R: Read>(reader: R) -> Result<Bytes, String> {
    let mut out = Vec::new();
    let mut limited = reader.take(MAX_DECODED_BYTES as u64 + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|error| error.to_string())?;
    if out.len() > MAX_DECODED_BYTES {
        return Err(format!(
            "decoded body exceeds {MAX_DECODED_BYTES} bytes; keeping raw body"
        ));
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{CONTENT_LENGTH, HeaderValue};

    const PLAIN: &str = r#"{"service":"billing","ok":true,"items":[1,2,3]}"#;

    const GZIP_FIXTURE: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 171, 86, 42, 78, 45, 42, 203, 76, 78, 85, 178, 82, 74,
        202, 204, 201, 201, 204, 75, 87, 210, 81, 202, 207, 86, 178, 42, 41, 42, 77, 213, 81, 202,
        44, 73, 205, 45, 86, 178, 138, 54, 212, 49, 210, 49, 142, 173, 5, 0, 52, 12, 114, 78, 47,
        0, 0, 0,
    ];

    const ZLIB_FIXTURE: &[u8] = &[
        120, 156, 171, 86, 42, 78, 45, 42, 203, 76, 78, 85, 178, 82, 74, 202, 204, 201, 201, 204,
        75, 87, 210, 81, 202, 207, 86, 178, 42, 41, 42, 77, 213, 81, 202, 44, 73, 205, 45, 86, 178,
        138, 54, 212, 49, 210, 49, 142, 173, 5, 0, 126, 166, 15, 67,
    ];

    const RAW_DEFLATE_FIXTURE: &[u8] = &[
        171, 86, 42, 78, 45, 42, 203, 76, 78, 85, 178, 82, 74, 202, 204, 201, 201, 204, 75, 87, 210,
        81, 202, 207, 86, 178, 42, 41, 42, 77, 213, 81, 202, 44, 73, 205, 45, 86, 178, 138, 54, 212,
        49, 210, 49, 142, 173, 5, 0,
    ];

    const DOUBLE_GZIP_FIXTURE: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 147, 239, 230, 96, 0, 1, 38, 230, 213, 97, 90, 126, 186,
        90, 167, 125, 252, 66, 55, 5, 121, 157, 58, 115, 242, 228, 25, 239, 240, 75, 129, 167, 206,
        135, 109, 210, 210, 212, 242, 189, 26, 120, 74, 199, 243, 172, 110, 216, 166, 46, 179, 43,
        134, 151, 12, 251, 214, 178, 50, 152, 240, 20, 249, 233, 3, 181, 2, 0, 173, 148, 162, 111,
        67, 0, 0, 0,
    ];

    fn headers_with_encoding(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn assert_plain(decoded: &DecodedBody) {
        assert_eq!(decoded.status, DecodeStatus::Decoded);
        assert_eq!(decoded.body.as_ref(), PLAIN.as_bytes());
    }

    #[test]
    fn unencoded_body_is_returned_as_is() {
        let body = Bytes::from_static(b"hello");
        let decoded = decoded_body(&HeaderMap::new(), &body);
        assert_eq!(decoded.status, DecodeStatus::NotEncoded);
        assert_eq!(decoded.body, body);
        assert!(decoded.codings.is_empty());
    }

    #[test]
    fn identity_is_not_a_coding() {
        let headers = headers_with_encoding("identity");
        let body = Bytes::from_static(b"hello");
        let decoded = decoded_body(&headers, &body);
        assert_eq!(decoded.status, DecodeStatus::NotEncoded);
        assert!(decoded.codings.is_empty());
    }

    #[test]
    fn decodes_gzip() {
        let decoded = decoded_body(
            &headers_with_encoding("gzip"),
            &Bytes::from_static(GZIP_FIXTURE),
        );
        assert_plain(&decoded);
        assert_eq!(decoded.codings, vec!["gzip".to_string()]);
    }

    #[test]
    fn decodes_x_gzip_alias() {
        let decoded = decoded_body(
            &headers_with_encoding("x-gzip"),
            &Bytes::from_static(GZIP_FIXTURE),
        );
        assert_plain(&decoded);
    }

    #[test]
    fn decodes_zlib_deflate() {
        let decoded = decoded_body(
            &headers_with_encoding("deflate"),
            &Bytes::from_static(ZLIB_FIXTURE),
        );
        assert_plain(&decoded);
    }

    #[test]
    fn decodes_raw_deflate_as_a_fallback() {
        let decoded = decoded_body(
            &headers_with_encoding("deflate"),
            &Bytes::from_static(RAW_DEFLATE_FIXTURE),
        );
        assert_plain(&decoded);
    }

    #[test]
    fn decodes_stacked_codings_outermost_first() {
        // `Content-Encoding: gzip, gzip` means the body was gzipped twice; the
        // decoder must unwrap in reverse order rather than once.
        let decoded = decoded_body(
            &headers_with_encoding("gzip, gzip"),
            &Bytes::from_static(DOUBLE_GZIP_FIXTURE),
        );
        assert_plain(&decoded);
        assert_eq!(decoded.codings, vec!["gzip".to_string(), "gzip".to_string()]);
    }

    #[test]
    fn decodes_multi_value_header() {
        let headers = headers_with_encoding("identity, gzip");
        let decoded = decoded_body(&headers, &Bytes::from_static(GZIP_FIXTURE));
        assert_plain(&decoded);
        assert_eq!(decoded.codings, vec!["gzip".to_string()]);
    }

    #[test]
    fn unknown_coding_is_reported_not_guessed() {
        let decoded = decoded_body(
            &headers_with_encoding("compress"),
            &Bytes::from_static(b"raw"),
        );
        assert_eq!(decoded.status, DecodeStatus::Unsupported);
        assert_eq!(decoded.body.as_ref(), b"raw");
    }

    #[test]
    fn corrupt_body_keeps_raw_bytes() {
        let corrupt = Bytes::from_static(&[31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 9, 9, 9]);
        let decoded = decoded_body(&headers_with_encoding("gzip"), &corrupt);
        assert_eq!(decoded.status, DecodeStatus::Failed);
        assert_eq!(decoded.body, corrupt);
    }

    #[test]
    fn empty_encoded_body_is_not_an_error() {
        let decoded = decoded_body(&headers_with_encoding("gzip"), &Bytes::new());
        assert_eq!(decoded.status, DecodeStatus::EmptyBody);
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn decoding_never_panics_on_hostile_input() {
        let fixtures: [&[u8]; 6] = [
            GZIP_FIXTURE,
            ZLIB_FIXTURE,
            RAW_DEFLATE_FIXTURE,
            DOUBLE_GZIP_FIXTURE,
            &[0u8; 32],
            &[0xff; 32],
        ];
        for fixture in fixtures {
            for coding in ["gzip", "deflate", "br", "zstd"] {
                let _ = decoded_body(&headers_with_encoding(coding), &Bytes::copy_from_slice(fixture));
            }
        }
    }

    #[test]
    fn decoded_headers_drop_stale_encoding_and_length() {
        let mut headers = headers_with_encoding("gzip");
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("67"));
        let decoded = decoded_body(&headers, &Bytes::from_static(GZIP_FIXTURE));
        let sanitized = headers_for_decoded_body(&headers, &decoded);
        assert!(!sanitized.contains_key(CONTENT_ENCODING));
        assert!(!sanitized.contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn plain_headers_are_untouched() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        let decoded = decoded_body(&headers, &Bytes::from_static(b"hello"));
        let sanitized = headers_for_decoded_body(&headers, &decoded);
        assert_eq!(
            sanitized.get(CONTENT_LENGTH).and_then(|value| value.to_str().ok()),
            Some("5")
        );
    }
}
