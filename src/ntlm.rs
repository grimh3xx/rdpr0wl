//! NTLMv2 cryptography — the core of NLA/CredSSP authentication.
//!
//! Verified against the official MS-NLMP reference vectors (section 4.2.4), so
//! the cryptographic heart of credential validation is proven even though the
//! full CredSSP transport needs a live NLA host to exercise end to end.
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(uppercase(user) + domain)).
pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let nt_hash = Md4::digest(utf16le(password)); // 16-byte NTLM hash
    let mut mac = HmacMd5::new_from_slice(&nt_hash).expect("HMAC key");
    let mut ident = utf16le(&user.to_uppercase());
    ident.extend_from_slice(&utf16le(domain));
    mac.update(&ident);
    mac.finalize().into_bytes().into()
}

/// Computes the NTLMv2 response: returns (NTProofStr[16], blob) where the full
/// NtChallengeResponse is `NTProofStr || blob`.
pub fn ntlmv2_response(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: &[u8; 8],
    target_info: &[u8],
) -> ([u8; 16], Vec<u8>) {
    // "temp" (MS-NLMP 2.2.2.7 NTLMv2_CLIENT_CHALLENGE)
    let mut temp = vec![0x01, 0x01, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(timestamp);
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0, 0, 0, 0]);
    temp.extend_from_slice(target_info);
    temp.extend_from_slice(&[0, 0, 0, 0]);

    let mut mac = HmacMd5::new_from_slice(response_key).expect("HMAC key");
    mac.update(server_challenge);
    mac.update(&temp);
    let proof: [u8; 16] = mac.finalize().into_bytes().into();
    (proof, temp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // MS-NLMP 4.2.4.2.2 — NTOWFv2 for User/Domain/Password.
    #[test]
    fn ntowf_v2_matches_ms_vector() {
        let key = ntowf_v2("Password", "User", "Domain");
        assert_eq!(hx(&key), "0c868a403bfd7a93a3001ef22ef02e3f");
    }

    // MS-NLMP 4.2.4.2.3 — NTProofStr for the reference inputs.
    #[test]
    fn ntproofstr_matches_ms_vector() {
        let key = ntowf_v2("Password", "User", "Domain");
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge = [0xaa; 8];
        let timestamp = [0u8; 8];
        // TargetInfo from MS-NLMP 4.2.4.1.3
        let target_info = [
            0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00,
            0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let (proof, _blob) =
            ntlmv2_response(&key, &server_challenge, &client_challenge, &timestamp, &target_info);
        assert_eq!(hx(&proof), "68cd0ab851e51c96aabc927bebef6a1c");
    }
}
