//! Negociação X.224/RDP (TPKT + Connection Request) para descobrir a postura
//! de segurança do host: RDP puro, TLS, ou CredSSP/NLA obrigatório.
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const PROTOCOL_RDP: u32 = 0x0000_0000;
pub const PROTOCOL_SSL: u32 = 0x0000_0001;
pub const PROTOCOL_HYBRID: u32 = 0x0000_0002; // CredSSP / NLA
pub const PROTOCOL_HYBRID_EX: u32 = 0x0000_0008;

#[derive(Debug)]
pub enum Posture {
    /// Servidor selecionou um protocolo (bitmask MS-RDPBCGR).
    Selected(u32),
    /// Negociação falhou com código.
    Failure(u32),
    /// Resposta sem estrutura de negociação (RDP legado).
    Legacy,
}

/// Monta o Connection Request pedindo TLS + CredSSP.
fn build_cr(requested: u32) -> Vec<u8> {
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
    let li = (6 + neg.len()) as u8; // bytes após o LI
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

fn parse_response(resp: &[u8]) -> Posture {
    // TPKT(4) + X224 CC fixo(7) => negociação em 11
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
        .map_err(|_| anyhow!("timeout conectando"))??;
    let cr = build_cr(PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX);
    s.write_all(&cr).await?;
    let mut buf = [0u8; 64];
    let n = timeout(to, s.read(&mut buf)).await.map_err(|_| anyhow!("timeout lendo"))??;
    if n == 0 {
        return Err(anyhow!("conexão fechada sem resposta"));
    }
    Ok(parse_response(&buf[..n]))
}

pub fn describe(p: &Posture) -> String {
    match p {
        Posture::Selected(v) => {
            let mut parts = Vec::new();
            if *v == PROTOCOL_RDP {
                parts.push("RDP padrão (sem TLS — inseguro)".to_string());
            }
            if v & PROTOCOL_SSL != 0 {
                parts.push("TLS".to_string());
            }
            if v & PROTOCOL_HYBRID != 0 {
                parts.push("CredSSP/NLA obrigatório".to_string());
            }
            if v & PROTOCOL_HYBRID_EX != 0 {
                parts.push("CredSSP-EX".to_string());
            }
            format!("selecionou: {} (0x{:08x})", parts.join(" + "), v)
        }
        Posture::Failure(code) => {
            let reason = match code {
                0x01 => "SSL_REQUIRED_BY_SERVER",
                0x02 => "SSL_NOT_ALLOWED_BY_SERVER",
                0x03 => "SSL_CERT_NOT_ON_SERVER",
                0x04 => "INCONSISTENT_FLAGS",
                0x05 => "HYBRID_REQUIRED_BY_SERVER",
                _ => "desconhecido",
            };
            format!("negociação falhou: {reason} (0x{code:08x})")
        }
        Posture::Legacy => "sem estrutura de negociação (RDP legado / Windows antigo)".to_string(),
    }
}
