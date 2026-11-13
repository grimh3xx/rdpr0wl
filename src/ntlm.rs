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

// ---------------------------------------------------------------------------
// NTLM message construction + NTLMSSP signing/sealing for CredSSP.
// ---------------------------------------------------------------------------
use md5::Md5 as Md5Hash;

pub const NEG_UNICODE: u32 = 0x0000_0001;
pub const NEG_SIGN: u32 = 0x0000_0010;
pub const NEG_SEAL: u32 = 0x0000_0020;
pub const NEG_NTLM: u32 = 0x0000_0200;
pub const NEG_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NEG_EXT_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEG_TARGET_INFO: u32 = 0x0080_0000;
pub const NEG_128: u32 = 0x2000_0000;
pub const NEG_KEY_EXCH: u32 = 0x4000_0000;
pub const NEG_56: u32 = 0x8000_0000;
pub const NEG_REQUEST_TARGET: u32 = 0x0000_0004;

fn md5(data: &[u8]) -> [u8; 16] {
    use md4::Digest;
    Md5Hash::digest(data).into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = Hmac::<Md5>::new_from_slice(key).expect("key");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Stateful RC4 keystream (used for NTLMSSP sealing).
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }
    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s
                [(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            out.push(b ^ k);
        }
        out
    }
}

/// One-shot RC4 (stateless), for the key-exchange wrap.
fn rc4_once(key: &[u8], data: &[u8]) -> Vec<u8> {
    Rc4::new(key).apply(data)
}

fn sec_field(len: usize, off: u32) -> [u8; 8] {
    let l = len as u16;
    let mut v = [0u8; 8];
    v[0..2].copy_from_slice(&l.to_le_bytes());
    v[2..4].copy_from_slice(&l.to_le_bytes());
    v[4..8].copy_from_slice(&off.to_le_bytes());
    v
}

/// NTLMSSP NEGOTIATE (Type 1).
pub fn type1() -> Vec<u8> {
    let flags = NEG_UNICODE
        | NEG_REQUEST_TARGET
        | NEG_NTLM
        | NEG_SIGN
        | NEG_SEAL
        | NEG_ALWAYS_SIGN
        | NEG_EXT_SESSIONSECURITY
        | NEG_TARGET_INFO
        | NEG_128
        | NEG_KEY_EXCH
        | NEG_56;
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[0u8; 8]); // DomainName fields
    m.extend_from_slice(&[0u8; 8]); // Workstation fields
    m
}

pub struct Challenge {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
    pub flags: u32,
}

/// Parses a CHALLENGE (Type 2) message.
pub fn parse_challenge(m: &[u8]) -> Option<Challenge> {
    if m.len() < 48 || &m[0..8] != b"NTLMSSP\0" {
        return None;
    }
    if u32::from_le_bytes([m[8], m[9], m[10], m[11]]) != 2 {
        return None;
    }
    let flags = u32::from_le_bytes([m[20], m[21], m[22], m[23]]);
    let mut sc = [0u8; 8];
    sc.copy_from_slice(&m[24..32]);
    let ti_len = u16::from_le_bytes([m[40], m[41]]) as usize;
    let ti_off = u32::from_le_bytes([m[44], m[45], m[46], m[47]]) as usize;
    let target_info = m.get(ti_off..ti_off.checked_add(ti_len)?)?.to_vec();
    Some(Challenge { server_challenge: sc, target_info, flags })
}

fn av_timestamp(target_info: &[u8]) -> [u8; 8] {
    let mut i = 0;
    while i + 4 <= target_info.len() {
        let id = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
        let len = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
        if id == 0x0007 && i + 4 + 8 <= target_info.len() {
            let mut t = [0u8; 8];
            t.copy_from_slice(&target_info[i + 4..i + 12]);
            return t;
        }
        if id == 0x0000 {
            break;
        }
        i += 4 + len;
    }
    [0u8; 8]
}

/// Per-direction sealing/signing context (NTLMSSP extended session security).
pub struct Seal {
    rc4: Rc4,
    sign_key: [u8; 16],
    seq: u32,
    key_exch: bool,
}

impl Seal {
    pub fn new(seal_key: [u8; 16], sign_key: [u8; 16], key_exch: bool) -> Self {
        Seal { rc4: Rc4::new(&seal_key), sign_key, seq: 0, key_exch }
    }
    /// Seals a message -> signature(16) || ciphertext.
    pub fn seal(&mut self, msg: &[u8]) -> Vec<u8> {
        let sealed = self.rc4.apply(msg);
        let mut tosign = self.seq.to_le_bytes().to_vec();
        tosign.extend_from_slice(msg);
        let mut cksum = hmac_md5(&self.sign_key, &tosign)[0..8].to_vec();
        if self.key_exch {
            cksum = self.rc4.apply(&cksum);
        }
        let mut sig = vec![1u8, 0, 0, 0];
        sig.extend_from_slice(&cksum);
        sig.extend_from_slice(&self.seq.to_le_bytes());
        self.seq = self.seq.wrapping_add(1);
        sig.extend_from_slice(&sealed);
        sig
    }
    /// Unseals signature(16) || ciphertext -> plaintext if the MAC checks out.
    pub fn unseal(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 16 {
            return None;
        }
        let sig = &buf[0..16];
        let msg = self.rc4.apply(&buf[16..]);
        let mut tosign = self.seq.to_le_bytes().to_vec();
        tosign.extend_from_slice(&msg);
        let recomputed = hmac_md5(&self.sign_key, &tosign)[0..8].to_vec();
        let sig_cksum = if self.key_exch {
            self.rc4.apply(&sig[4..12])
        } else {
            sig[4..12].to_vec()
        };
        if sig_cksum != recomputed || sig[12..16] != self.seq.to_le_bytes() {
            return None;
        }
        self.seq = self.seq.wrapping_add(1);
        Some(msg)
    }
}

/// Result of building the AUTHENTICATE message: the Type 3 bytes plus the two
/// per-direction sealing contexts (client->server and server->client).
pub struct Authenticate {
    pub type3: Vec<u8>,
    pub client_seal: Seal,
    pub server_seal: Seal,
    pub exported_session_key: [u8; 16],
}

fn derive(exported: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut v = exported.to_vec();
    v.extend_from_slice(magic);
    md5(&v)
}

/// Builds the NTLMSSP AUTHENTICATE (Type 3) with NTLMv2 and derives the sealing
/// keys. `exported_override` forces the random session key (for deterministic
/// tests); otherwise it is random.
pub fn build_authenticate(
    user: &str,
    domain: &str,
    password: &str,
    chal: &Challenge,
    client_challenge: [u8; 8],
    exported_override: Option<[u8; 16]>,
) -> Authenticate {
    let key = ntowf_v2(password, user, domain);
    let ts = av_timestamp(&chal.target_info);
    let (proof, blob) =
        ntlmv2_response(&key, &chal.server_challenge, &client_challenge, &ts, &chal.target_info);
    let mut nt_response = proof.to_vec();
    nt_response.extend_from_slice(&blob);

    // LMv2
    let mut lm_in = chal.server_challenge.to_vec();
    lm_in.extend_from_slice(&client_challenge);
    let mut lm_response = hmac_md5(&key, &lm_in).to_vec();
    lm_response.extend_from_slice(&client_challenge);

    let session_base_key = hmac_md5(&key, &proof);
    let key_exch = chal.flags & NEG_KEY_EXCH != 0;
    let exported = if key_exch {
        exported_override.unwrap_or_else(|| {
            let mut k = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
            k
        })
    } else {
        session_base_key
    };
    let encrypted_session_key = if key_exch {
        rc4_once(&session_base_key, &exported)
    } else {
        Vec::new()
    };

    let dom = utf16le(domain);
    let usr = utf16le(user);
    let base = 64u32;
    let mut off = base;
    let lm_f = sec_field(lm_response.len(), off);
    off += lm_response.len() as u32;
    let nt_f = sec_field(nt_response.len(), off);
    off += nt_response.len() as u32;
    let dom_f = sec_field(dom.len(), off);
    off += dom.len() as u32;
    let usr_f = sec_field(usr.len(), off);
    off += usr.len() as u32;
    let ws_f = sec_field(0, off);
    let key_f = sec_field(encrypted_session_key.len(), off);

    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&3u32.to_le_bytes());
    m.extend_from_slice(&lm_f);
    m.extend_from_slice(&nt_f);
    m.extend_from_slice(&dom_f);
    m.extend_from_slice(&usr_f);
    m.extend_from_slice(&ws_f);
    m.extend_from_slice(&key_f);
    m.extend_from_slice(&chal.flags.to_le_bytes());
    // payload
    m.extend_from_slice(&lm_response);
    m.extend_from_slice(&nt_response);
    m.extend_from_slice(&dom);
    m.extend_from_slice(&usr);
    m.extend_from_slice(&encrypted_session_key);

    let (client_seal, server_seal) = derive_seals(&exported, key_exch);
    Authenticate { type3: m, client_seal, server_seal, exported_session_key: exported }
}

/// Derives the (client->server, server->client) sealing contexts from the
/// exported session key. Both peers call this to interoperate.
pub fn derive_seals(exported: &[u8; 16], key_exch: bool) -> (Seal, Seal) {
    let c_sign = derive(exported, b"session key to client-to-server signing key magic constant\0");
    let c_seal = derive(exported, b"session key to client-to-server sealing key magic constant\0");
    let s_sign = derive(exported, b"session key to server-to-client signing key magic constant\0");
    let s_seal = derive(exported, b"session key to server-to-client sealing key magic constant\0");
    (Seal::new(c_seal, c_sign, key_exch), Seal::new(s_seal, s_sign, key_exch))
}

/// NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp(blob)).
pub fn ntproofstr(key: &[u8; 16], server_challenge: &[u8; 8], blob: &[u8]) -> [u8; 16] {
    let mut d = server_challenge.to_vec();
    d.extend_from_slice(blob);
    hmac_md5(key, &d)
}

/// SessionBaseKey (NTLMv2) = HMAC_MD5(ResponseKeyNT, NTProofStr).
pub fn session_base_key(key: &[u8; 16], proof: &[u8; 16]) -> [u8; 16] {
    hmac_md5(key, proof)
}

fn utf16_decode(b: &[u8]) -> String {
    let u: Vec<u16> = b.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&u)
}

fn secf(m: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos + 8 > m.len() {
        return None;
    }
    let len = u16::from_le_bytes([m[pos], m[pos + 1]]) as usize;
    let off = u32::from_le_bytes([m[pos + 4], m[pos + 5], m[pos + 6], m[pos + 7]]) as usize;
    Some((len, off))
}

/// Builds a CHALLENGE (Type 2) message (server side).
pub fn build_challenge(server_challenge: [u8; 8], target_info: &[u8], flags: u32) -> Vec<u8> {
    let tn = utf16le("LAB");
    let base = 48u32;
    let ti_off = base + tn.len() as u32;
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&sec_field(tn.len(), base));
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&server_challenge);
    m.extend_from_slice(&[0u8; 8]); // reserved
    m.extend_from_slice(&sec_field(target_info.len(), ti_off));
    m.extend_from_slice(&tn);
    m.extend_from_slice(target_info);
    m
}

pub struct Type3Msg {
    pub user: String,
    pub domain: String,
    pub nt_response: Vec<u8>,
    pub flags: u32,
}

/// Parses an AUTHENTICATE (Type 3) message (server side).
pub fn parse_type3(m: &[u8]) -> Option<Type3Msg> {
    if m.len() < 64 || &m[0..8] != b"NTLMSSP\0" {
        return None;
    }
    if u32::from_le_bytes([m[8], m[9], m[10], m[11]]) != 3 {
        return None;
    }
    let (nt_len, nt_off) = secf(m, 20)?;
    let (dom_len, dom_off) = secf(m, 28)?;
    let (usr_len, usr_off) = secf(m, 36)?;
    let flags = u32::from_le_bytes([m[60], m[61], m[62], m[63]]);
    let nt_response = m.get(nt_off..nt_off + nt_len)?.to_vec();
    let domain = utf16_decode(m.get(dom_off..dom_off + dom_len)?);
    let user = utf16_decode(m.get(usr_off..usr_off + usr_len)?);
    Some(Type3Msg { user, domain, nt_response, flags })
}


#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Well-known RC4 test vector (Wikipedia / common): RC4("Key","Plaintext").
    #[test]
    fn rc4_known_vector() {
        assert_eq!(hx(&rc4_once(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
    }

    #[test]
    fn seal_unseal_roundtrip_key_exch() {
        let mut tx = Seal::new([1u8; 16], [2u8; 16], true);
        let mut rx = Seal::new([1u8; 16], [2u8; 16], true);
        for msg in [&b"hello"[..], b"second message", b"third"] {
            let sealed = tx.seal(msg);
            assert_eq!(rx.unseal(&sealed).as_deref(), Some(msg));
        }
    }

    #[test]
    fn seal_unseal_roundtrip_no_key_exch() {
        let mut tx = Seal::new([9u8; 16], [8u8; 16], false);
        let mut rx = Seal::new([9u8; 16], [8u8; 16], false);
        let sealed = tx.seal(b"public key bytes");
        assert_eq!(rx.unseal(&sealed).as_deref(), Some(&b"public key bytes"[..]));
    }

    #[test]
    fn tampered_seal_is_rejected() {
        let mut tx = Seal::new([1u8; 16], [2u8; 16], true);
        let mut rx = Seal::new([1u8; 16], [2u8; 16], true);
        let mut sealed = tx.seal(b"data");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(rx.unseal(&sealed).is_none());
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
