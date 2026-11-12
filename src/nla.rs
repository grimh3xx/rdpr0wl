//! Validação de credencial via CredSSP/NLA.
//!
//! PLANEJADO. O caminho completo exige: TLS (rustls) sobre o socket após o
//! Connection Confirm, seguido do sub-protocolo CredSSP (TSRequest ASN.1 DER)
//! carregando a troca NTLMSSP/SPNEGO e, por fim, a validação da senha.
//!
//! Depêndencias previstas: rustls + tokio-rustls, uma impl NTLM, e um
//! codificador DER. Deixado explícito para não fingir resultado.
use anyhow::{bail, Result};
use std::time::Duration;

pub async fn check(_host: &str, _port: u16, _user: &str, _pass: &str, _to: Duration) -> Result<bool> {
    bail!("validação NLA/CredSSP ainda não implementada (roadmap: rustls + CredSSP)")
}
