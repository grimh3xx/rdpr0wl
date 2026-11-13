//! Minimal DER encoder/decoder for the CredSSP TSRequest (MS-CSSP 2.2.1).
//!
//! ```text
//! TSRequest ::= SEQUENCE {
//!     version    [0] INTEGER,
//!     negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING } OPTIONAL,
//!     authInfo   [2] OCTET STRING OPTIONAL,
//!     pubKeyAuth [3] OCTET STRING OPTIONAL,
//!     errorCode  [4] INTEGER OPTIONAL }
//! ```

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 128 {
        v.push(n as u8);
    } else if n < 256 {
        v.push(0x81);
        v.push(n as u8);
    } else {
        v.push(0x82);
        v.push((n >> 8) as u8);
        v.push(n as u8);
    }
    v.extend_from_slice(content);
    v
}

fn der_int(v: u32) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > 1 && b[0] == 0 {
        b.remove(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0); // keep it positive
    }
    der(0x02, &b)
}

#[derive(Default)]
pub struct TsRequest {
    pub version: u32,
    pub nego_token: Option<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
}

impl TsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = der(0xA0, &der_int(self.version));
        if let Some(t) = &self.nego_token {
            let token = der(0xA0, &der(0x04, t)); // negoToken [0] OCTET STRING
            let item = der(0x30, &token); // SEQUENCE
            let seq = der(0x30, &item); // SEQUENCE OF
            body.extend(der(0xA1, &seq));
        }
        if let Some(a) = &self.auth_info {
            body.extend(der(0xA2, &der(0x04, a)));
        }
        if let Some(p) = &self.pub_key_auth {
            body.extend(der(0xA3, &der(0x04, p)));
        }
        if let Some(e) = self.error_code {
            body.extend(der(0xA4, &der_int(e)));
        }
        der(0x30, &body)
    }
}

/// Reads one TLV: returns (tag, content, total_consumed).
fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let (len, hdr) = if buf[1] < 128 {
        (buf[1] as usize, 2)
    } else if buf[1] == 0x81 {
        (*buf.get(2)? as usize, 3)
    } else if buf[1] == 0x82 {
        ((*buf.get(2)? as usize) << 8 | *buf.get(3)? as usize, 4)
    } else {
        return None;
    };
    let content = buf.get(hdr..hdr + len)?;
    Some((tag, content, hdr + len))
}

fn read_int(buf: &[u8]) -> u32 {
    buf.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32)
}

pub fn parse(buf: &[u8]) -> Option<TsRequest> {
    let (tag, body, _) = read_tlv(buf)?;
    if tag != 0x30 {
        return None;
    }
    let mut out = TsRequest::default();
    let mut rest = body;
    while !rest.is_empty() {
        let (t, content, used) = read_tlv(rest)?;
        match t {
            0xA0 => {
                let (_, iv, _) = read_tlv(content)?;
                out.version = read_int(iv);
            }
            0xA1 => {
                // SEQUENCE OF SEQUENCE { [0] OCTET STRING }
                let (_, seqof, _) = read_tlv(content)?;
                let (_, item, _) = read_tlv(seqof)?;
                let (_, tok0, _) = read_tlv(item)?;
                let (_, octets, _) = read_tlv(tok0)?;
                out.nego_token = Some(octets.to_vec());
            }
            0xA2 => {
                let (_, oct, _) = read_tlv(content)?;
                out.auth_info = Some(oct.to_vec());
            }
            0xA3 => {
                let (_, oct, _) = read_tlv(content)?;
                out.pub_key_auth = Some(oct.to_vec());
            }
            0xA4 => {
                let (_, iv, _) = read_tlv(content)?;
                out.error_code = Some(read_int(iv));
            }
            _ => {}
        }
        rest = &rest[used..];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_nego_and_pubkey() {
        let req = TsRequest {
            version: 6,
            nego_token: Some(b"NTLMSSP\0token".to_vec()),
            pub_key_auth: Some(vec![1, 2, 3, 4, 5]),
            error_code: None,
            auth_info: None,
        };
        let enc = req.encode();
        let got = parse(&enc).unwrap();
        assert_eq!(got.version, 6);
        assert_eq!(got.nego_token.as_deref(), Some(&b"NTLMSSP\0token"[..]));
        assert_eq!(got.pub_key_auth, Some(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn roundtrip_error_code() {
        let req = TsRequest {
            version: 3,
            error_code: Some(0xC000_006D),
            ..Default::default()
        };
        let got = parse(&req.encode()).unwrap();
        assert_eq!(got.error_code, Some(0xC000_006D));
    }
}
