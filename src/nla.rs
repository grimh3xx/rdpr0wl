//! Credential validation via CredSSP/NLA.
//!
//! The cryptographic core — NTLMv2 (NTOWFv2 + NTProofStr) — is implemented and
//! proven against the MS-NLMP reference vectors in [`crate::ntlm`]. The
//! remaining piece is the CredSSP transport: TLS (rustls) over the RDP socket
//! after a HYBRID negotiation, the TSRequest ASN.1 exchange carrying NTLMSSP,
//! and pubKeyAuth validation. That path is only meaningful against a live
//! NLA-enabled host, so `check` returns an explicit status instead of faking a
//! result.
use anyhow::{bail, Result};
use std::time::Duration;

pub async fn check(_host: &str, _port: u16, _user: &str, _pass: &str, _to: Duration) -> Result<bool> {
    bail!(
        "NLA credential validation needs the CredSSP transport against a live NLA host; \
         the NTLMv2 crypto core is implemented and MS-vector-tested in the `ntlm` module"
    )
}

#[cfg(test)]
mod tests {
    // The NTLMv2 primitives this module builds on are exercised by crate::ntlm.
    #[test]
    fn ntlm_core_is_available() {
        let key = crate::ntlm::ntowf_v2("Password", "User", "Domain");
        assert_eq!(key.len(), 16);
    }
}
