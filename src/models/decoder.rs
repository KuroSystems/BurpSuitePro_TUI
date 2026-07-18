use base64::{engine::general_purpose, Engine as _};
use md5::Md5;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderTransform {
    Base64Encode,
    Base64Decode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    HtmlDecode,
    Sha256,
    Md5,
    JwtDecode,
    JsonPrettyPrint,
}

impl DecoderTransform {
    pub const ALL: [Self; 11] = [
        Self::Base64Encode,
        Self::Base64Decode,
        Self::HexEncode,
        Self::HexDecode,
        Self::UrlEncode,
        Self::UrlDecode,
        Self::HtmlDecode,
        Self::Sha256,
        Self::Md5,
        Self::JwtDecode,
        Self::JsonPrettyPrint,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Base64Encode => "Base64 Encode",
            Self::Base64Decode => "Base64 Decode",
            Self::HexEncode => "Hex Encode",
            Self::HexDecode => "Hex Decode",
            Self::UrlEncode => "URL Encode",
            Self::UrlDecode => "URL Decode",
            Self::HtmlDecode => "HTML Decode",
            Self::Sha256 => "SHA-256",
            Self::Md5 => "MD5",
            Self::JwtDecode => "JWT Decode",
            Self::JsonPrettyPrint => "JSON Pretty Print",
        }
    }

    pub fn from_index(index: usize) -> Self {
        Self::ALL[index % Self::ALL.len()]
    }

    pub fn apply(self, input: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Base64Encode => Ok(general_purpose::STANDARD.encode(input).into_bytes()),
            Self::Base64Decode => general_purpose::STANDARD
                .decode(trim_ascii(input))
                .map_err(|error| error.to_string()),
            Self::HexEncode => Ok(hex::encode(input).into_bytes()),
            Self::HexDecode => hex::decode(String::from_utf8_lossy(input).trim())
                .map_err(|error| error.to_string()),
            Self::UrlEncode => Ok(urlencoding::encode(&String::from_utf8_lossy(input)).into_owned().into_bytes()),
            Self::UrlDecode => urlencoding::decode(&String::from_utf8_lossy(input))
                .map(|value| value.into_owned().into_bytes())
                .map_err(|error| error.to_string()),
            Self::HtmlDecode => Ok(html_decode(&String::from_utf8_lossy(input)).into_bytes()),
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(input);
                Ok(hex::encode(hasher.finalize()).into_bytes())
            }
            Self::Md5 => {
                let mut hasher = Md5::new();
                hasher.update(input);
                Ok(hex::encode(hasher.finalize()).into_bytes())
            }
            Self::JwtDecode => jwt_decode(&String::from_utf8_lossy(input)),
            Self::JsonPrettyPrint => serde_json::from_slice::<serde_json::Value>(input)
                .and_then(|value| serde_json::to_string_pretty(&value))
                .map(|value| value.into_bytes())
                .map_err(|error| error.to_string()),
        }
    }
}

pub fn apply_chain(input: &str, chain: &[DecoderTransform]) -> Result<String, String> {
    let mut bytes = input.as_bytes().to_vec();
    for transform in chain {
        bytes = transform.apply(&bytes)?;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn trim_ascii(input: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = input.len();
    while start < end && input[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && input[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &input[start..end]
}

fn jwt_decode(input: &str) -> Result<Vec<u8>, String> {
    let parts = input.trim().split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Err("JWT must contain at least header and payload".to_string());
    }
    let decode_part = |part: &str| -> Result<String, String> {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .or_else(|_| general_purpose::URL_SAFE.decode(part))
            .map_err(|error| error.to_string())?;
        serde_json::from_slice::<serde_json::Value>(&decoded)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .map_err(|error| error.to_string())
    };
    let header = decode_part(parts[0])?;
    let payload = decode_part(parts[1])?;
    Ok(format!("Header:\n{header}\n\nPayload:\n{payload}").into_bytes())
}

fn html_decode(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
