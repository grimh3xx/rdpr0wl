//! X.224/RDP negotiation (TPKT + Connection Request) to discover a host's
//! security posture: plain RDP, TLS, or mandatory CredSSP/NLA.
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const PROTOCOL_RDP: u32 = 0x0000_0000;
pub const PROTOCOL_SSL: u32 = 0x0000_0001;
pub const PROTOCOL_HYBRID: u32 = 0x0000_0002; // CredSSP / NLA
pub const PROTOCOL_HYBRID_EX: u32 = 0x0000_0008;

#[derive(Debug, PartialEq, Eq)]
pub enum Posture {
    /// Server selected a protocol (MS-RDPBCGR bitmask).
    Selected(u32),
    /// Negotiation failed with a code.
    Failure(u32),
    /// Response carried no negotiation structure (legacy RDP).
    Legacy,
}

/// Builds the Connection Request asking for TLS + CredSSP.
pub fn build_cr(requested: u32) -> Vec<u8> {
    let neg = {
        let mut v = Vec::with_capacity(8);
        v.push(0x01); // TYPE_RDP_NEG_REQ
        v.push(0x00); // flags
        v.extend_from_slice(&8u16.to_le_bytes()); // length
        v.extend_from_slice(&requested.to_le_bytes());
        v
    };
    // X.224 Connection Request
    let mut x224 = Vec::new();
    let li = (6 + neg.len()) as u8; // bytes after the LI
    x224.push(li);
    x224.push(0xE0); // CR
    x224.extend_from_slice(&[0x00, 0x00]); // dst-ref
    x224.extend_from_slice(&[0x00, 0x00]); // src-ref
    x224.push(0x00); // class
    x224.extend_from_slice(&neg);

    // TPKT
    let total = (4 + x224.len()) as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&x224);
    pkt
}

/// Parses the negotiation outcome from a Connection Confirm response.
pub fn parse_response(resp: &[u8]) -> Posture {
    // TPKT(4) + X224 CC fixed(7) => negotiation structure at offset 11
    if resp.len() >= 19 && resp[0] == 0x03 {
        let t = resp[11];
        let val = u32::from_le_bytes([resp[15], resp[16], resp[17], resp[18]]);
        return match t {
            0x02 => Posture::Selected(val),
            0x03 => Posture::Failure(val),
            _ => Posture::Legacy,
        };
    }
    Posture::Legacy
}

pub async fn probe(host: &str, port: u16, to: Duration) -> Result<Posture> {
    let mut s = timeout(to, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow!("timeout connecting"))??;
    let _ = s.set_nodelay(true);
    let cr = build_cr(PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX);
    s.write_all(&cr).await?;
    // Read the full TPKT: 4-byte header then the declared length.
    let mut head = [0u8; 4];
    timeout(to, s.read_exact(&mut head))
        .await
        .map_err(|_| anyhow!("timeout reading"))??;
    if head[0] != 0x03 {
        return Ok(Posture::Legacy);
    }
    let total = u16::from_be_bytes([head[2], head[3]]) as usize;
    let mut rest = vec![0u8; total.saturating_sub(4)];
    if !rest.is_empty() {
        timeout(to, s.read_exact(&mut rest))
            .await
            .map_err(|_| anyhow!("timeout reading body"))??;
    }
    let mut full = head.to_vec();
    full.extend_from_slice(&rest);
    Ok(parse_response(&full))
}

pub fn describe(p: &Posture) -> String {
    match p {
        Posture::Selected(v) => {
            let mut parts = Vec::new();
            if *v == PROTOCOL_RDP {
                parts.push("plain RDP (no TLS — insecure)".to_string());
            }
            if v & PROTOCOL_SSL != 0 {
                parts.push("TLS".to_string());
            }
            if v & PROTOCOL_HYBRID != 0 {
                parts.push("CredSSP/NLA required".to_string());
            }
            if v & PROTOCOL_HYBRID_EX != 0 {
                parts.push("CredSSP-EX".to_string());
            }
            format!("selected: {} (0x{:08x})", parts.join(" + "), v)
        }
        Posture::Failure(code) => {
            let reason = match code {
                0x01 => "SSL_REQUIRED_BY_SERVER",
                0x02 => "SSL_NOT_ALLOWED_BY_SERVER",
                0x03 => "SSL_CERT_NOT_ON_SERVER",
                0x04 => "INCONSISTENT_FLAGS",
                0x05 => "HYBRID_REQUIRED_BY_SERVER",
                _ => "unknown",
            };
            format!("negotiation failed: {reason} (0x{code:08x})")
        }
        Posture::Legacy => "no negotiation structure (legacy RDP / old Windows)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cc_with(neg_type: u8, value: u32) -> Vec<u8> {
        let mut r = vec![0x03, 0x00, 0x00, 0x13]; // TPKT len 19
        r.extend_from_slice(&[0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00]); // X224 CC
        r.push(neg_type);
        r.push(0x00);
        r.extend_from_slice(&8u16.to_le_bytes());
        r.extend_from_slice(&value.to_le_bytes());
        r
    }

    #[test]
    fn selected_hybrid_is_nla() {
        let p = parse_response(&cc_with(0x02, PROTOCOL_SSL | PROTOCOL_HYBRID));
        assert_eq!(p, Posture::Selected(0x03));
        assert!(describe(&p).contains("CredSSP/NLA required"));
    }

    #[test]
    fn failure_code_is_decoded() {
        let p = parse_response(&cc_with(0x03, 0x05));
        assert_eq!(p, Posture::Failure(5));
        assert!(describe(&p).contains("HYBRID_REQUIRED_BY_SERVER"));
    }

    #[test]
    fn short_response_is_legacy() {
        assert_eq!(parse_response(&[0x03, 0x00, 0x00, 0x0b]), Posture::Legacy);
    }

    #[test]
    fn cr_is_well_formed() {
        let cr = build_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        assert_eq!(&cr[0..2], &[0x03, 0x00]); // TPKT
        assert_eq!(cr[5], 0xE0); // X224 CR
        assert_eq!(cr[11], 0x01); // RDP_NEG_REQ
    }
}
