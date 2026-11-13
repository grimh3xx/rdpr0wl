//! Credential validation via CredSSP/NLA.
//!
//! PLANNED. The full path requires: TLS (rustls) over the socket after the
//! Connection Confirm, then the CredSSP sub-protocol (TSRequest ASN.1 DER)
//! carrying the NTLMSSP/SPNEGO exchange, and finally password validation.
//!
//! Left explicit so it never fakes a result. Validating a live credential
//! needs a real NLA-enabled host, which the probe path does not.
use anyhow::{bail, Result};
use std::time::Duration;

pub async fn check(_host: &str, _port: u16, _user: &str, _pass: &str, _to: Duration) -> Result<bool> {
    bail!("NLA/CredSSP credential validation is not implemented yet (roadmap: rustls + CredSSP)")
}
