//! Credential validation via CredSSP/NLA.
//!
//! The full client is implemented: X.224 HYBRID negotiation, TLS, then the
//! CredSSP TSRequest/NTLMSSP exchange with pubKeyAuth binding. The NTLMv2
//! crypto core is proven against the MS-NLMP reference vectors (`crate::ntlm`),
//! and the end-to-end protocol logic is proven against an in-process CredSSP
//! peer (see tests). Interop with a production Windows NLA host is expected but
//! can only be confirmed against a live target.
use crate::{credssp, ntlm, rdp};
use anyhow::{anyhow, bail, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn send_ts<S: AsyncWriteExt + Unpin>(s: &mut S, req: &credssp::TsRequest) -> Result<()> {
    s.write_all(&req.encode()).await?;
    s.flush().await?;
    Ok(())
}

async fn read_ts<S: AsyncReadExt + Unpin>(s: &mut S) -> Result<credssp::TsRequest> {
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    let (len, extra) = if h[1] < 128 {
        (h[1] as usize, Vec::new())
    } else if h[1] == 0x81 {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await?;
        (b[0] as usize, b.to_vec())
    } else if h[1] == 0x82 {
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await?;
        (((b[0] as usize) << 8) | b[1] as usize, b.to_vec())
    } else {
        bail!("bad DER length");
    };
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await?;
    let mut full = vec![h[0], h[1]];
    full.extend(extra);
    full.extend(body);
    credssp::parse(&full).ok_or_else(|| anyhow!("malformed TSRequest"))
}

/// Runs the CredSSP client over an established (TLS) stream, binding to the
/// server's public key. Returns Ok(true) if the credential is accepted.
pub async fn credssp_authenticate<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    user: &str,
    domain: &str,
    password: &str,
    pub_key: &[u8],
) -> Result<bool> {
    // 1) negoTokens = NTLM NEGOTIATE
    send_ts(
        stream,
        &credssp::TsRequest { version: 6, nego_token: Some(ntlm::type1()), ..Default::default() },
    )
    .await?;

    // 2) receive NTLM CHALLENGE
    let r = read_ts(stream).await?;
    let t2 = r.nego_token.ok_or_else(|| anyhow!("no challenge token"))?;
    let chal = ntlm::parse_challenge(&t2).ok_or_else(|| anyhow!("bad challenge"))?;

    // 3) build NTLM AUTHENTICATE
    let mut cc = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cc);
    let mut auth = ntlm::build_authenticate(user, domain, password, &chal, cc, None);

    // 4) send AUTHENTICATE + sealed pubKeyAuth
    let pka = auth.client_seal.seal(pub_key);
    send_ts(
        stream,
        &credssp::TsRequest {
            version: 6,
            nego_token: Some(auth.type3.clone()),
            pub_key_auth: Some(pka),
            ..Default::default()
        },
    )
    .await?;

    // 5) interpret the server's reply
    match read_ts(stream).await {
        Ok(resp) => {
            if let Some(e) = resp.error_code {
                if e != 0 {
                    return Ok(false);
                }
            }
            if let Some(p) = resp.pub_key_auth {
                if let Some(unsealed) = auth.server_seal.unseal(&p) {
                    let mut expect = pub_key.to_vec();
                    if let Some(first) = expect.first_mut() {
                        *first = first.wrapping_add(1);
                    }
                    return Ok(unsealed == expect);
                }
                return Ok(false);
            }
            Ok(false)
        }
        Err(_) => Ok(false), // server dropped the connection: credential rejected
    }
}

/// `rustls` verifier that accepts any certificate — we audit the credential,
/// not the server identity, and NLA pins to the cert via pubKeyAuth anyway.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ED25519,
        ]
    }
}

/// Validates a credential against a live NLA host: X.224 HYBRID -> TLS ->
/// CredSSP. Returns Ok(true) if the server accepts the credential.
pub async fn check(host: &str, port: u16, user: &str, password: &str, to: Duration) -> Result<bool> {
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;

    // user may be "DOMAIN\\user"
    let (domain, uname) = match user.split_once('\\') {
        Some((d, u)) => (d.to_string(), u.to_string()),
        None => (String::new(), user.to_string()),
    };

    let mut tcp = timeout(to, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow!("timeout connecting"))??;

    // X.224 Connection Request asking for CredSSP (HYBRID)
    tcp.write_all(&rdp::build_cr(rdp::PROTOCOL_SSL | rdp::PROTOCOL_HYBRID)).await?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    let total = u16::from_be_bytes([head[2], head[3]]) as usize;
    let mut rest = vec![0u8; total.saturating_sub(4)];
    tcp.read_exact(&mut rest).await?;
    let mut full = head.to_vec();
    full.extend_from_slice(&rest);
    match rdp::parse_response(&full) {
        rdp::Posture::Selected(p) if p & rdp::PROTOCOL_HYBRID != 0 => {}
        other => bail!("server did not select CredSSP/NLA: {}", rdp::describe(&other)),
    }

    // TLS over the same socket
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("bad server name"))?,
    };
    let mut tls = connector.connect(server_name, tcp).await?;

    // Bind to the server certificate's SubjectPublicKeyInfo
    let pub_key = {
        let (_, conn) = tls.get_ref();
        let certs = conn.peer_certificates().ok_or_else(|| anyhow!("no server cert"))?;
        let leaf = certs.first().ok_or_else(|| anyhow!("empty cert chain"))?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|_| anyhow!("cannot parse server cert"))?;
        parsed.public_key().raw.to_vec()
    };

    credssp_authenticate(&mut tls, &uname, &domain, password, &pub_key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    // In-process CredSSP peer: completes the exchange, accepting only `good_pass`.
    async fn credssp_server<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        s: &mut S,
        good_pass: &str,
        pub_key: &[u8],
    ) -> Result<()> {
        let _t1 = read_ts(s).await?; // NEGOTIATE
        let sc = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        // TargetInfo: NbDomain, NbComputer, Timestamp, EOL
        let dom = "LAB".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>();
        let mut ti = Vec::new();
        for (id, val) in [(0x0002u16, &dom), (0x0001u16, &dom)] {
            ti.extend_from_slice(&id.to_le_bytes());
            ti.extend_from_slice(&(val.len() as u16).to_le_bytes());
            ti.extend_from_slice(val);
        }
        ti.extend_from_slice(&0x0007u16.to_le_bytes()); // Timestamp
        ti.extend_from_slice(&8u16.to_le_bytes());
        ti.extend_from_slice(&[0u8; 8]);
        ti.extend_from_slice(&0u16.to_le_bytes()); // EOL
        ti.extend_from_slice(&0u16.to_le_bytes());
        let flags = ntlm::NEG_UNICODE
            | ntlm::NEG_NTLM
            | ntlm::NEG_EXT_SESSIONSECURITY
            | ntlm::NEG_TARGET_INFO
            | ntlm::NEG_ALWAYS_SIGN
            | ntlm::NEG_SIGN
            | ntlm::NEG_SEAL
            | ntlm::NEG_128
            | ntlm::NEG_56;
        let t2 = ntlm::build_challenge(sc, &ti, flags);
        send_ts(s, &credssp::TsRequest { version: 6, nego_token: Some(t2), ..Default::default() })
            .await?;

        let r2 = read_ts(s).await?;
        let t3 = r2.nego_token.ok_or_else(|| anyhow!("no auth"))?;
        let client_pka = r2.pub_key_auth.ok_or_else(|| anyhow!("no pubKeyAuth"))?;
        let parsed = ntlm::parse_type3(&t3).ok_or_else(|| anyhow!("bad type3"))?;

        let key = ntlm::ntowf_v2(good_pass, &parsed.user, &parsed.domain);
        let proof = &parsed.nt_response[0..16];
        let blob = &parsed.nt_response[16..];
        let expected = ntlm::ntproofstr(&key, &sc, blob);
        if expected != proof[..] {
            // wrong password
            send_ts(
                s,
                &credssp::TsRequest { version: 6, error_code: Some(0xC000_006D), ..Default::default() },
            )
            .await?;
            return Ok(());
        }
        let exported = ntlm::session_base_key(&key, &expected);
        let (mut client_dir, mut server_dir) = ntlm::derive_seals(&exported, false);
        let got = client_dir.unseal(&client_pka).ok_or_else(|| anyhow!("unseal failed"))?;
        if got != pub_key {
            bail!("pubKeyAuth mismatch");
        }
        let mut resp = pub_key.to_vec();
        if let Some(f) = resp.first_mut() {
            *f = f.wrapping_add(1);
        }
        let sealed = server_dir.seal(&resp);
        send_ts(
            s,
            &credssp::TsRequest { version: 6, pub_key_auth: Some(sealed), ..Default::default() },
        )
        .await?;
        Ok(())
    }

    async fn run_case(good_pass: &str, try_pass: &str) -> bool {
        let pub_key = b"server-public-key-info-DER-bytes".to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let gp = good_pass.to_string();
        let pk = pub_key.clone();
        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = credssp_server(&mut s, &gp, &pk).await;
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        let ok = credssp_authenticate(&mut c, "alice", "LAB", try_pass, &pub_key)
            .await
            .unwrap();
        let _ = srv.await;
        ok
    }

    #[tokio::test]
    async fn correct_password_is_accepted() {
        assert!(run_case("S3cret!", "S3cret!").await);
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        assert!(!run_case("S3cret!", "wrong").await);
    }
}
