<img src="docs/banner.svg" alt="rdpr0wl" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/rdpr0wl/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/rdpr0wl/actions)
[![license](https://img.shields.io/github/license/grimh3xx/rdpr0wl?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux%20%7C%20Windows-22D3EE?style=flat-square&labelColor=111826)
![authorised use](https://img.shields.io/badge/authorised%20use-only-F87171?style=flat-square&labelColor=111826)


**RDP security probe in Rust** for authorised pentests. It runs the X.224/RDP
negotiation and reveals the host's **security posture**: plain RDP (insecure),
TLS, or mandatory **CredSSP/NLA** — handy to prioritise targets and flag boxes
exposed to downgrade/bruteforce.

<p align="center"><img src="docs/demo.svg" alt="rdpr0wl demo" width="100%"></p>

> ## ⚠️ Authorised use only
> Run **only** against hosts you have explicit permission to test.

## Usage

```sh
rdpr0wl probe 10.0.0.10
rdpr0wl probe 10.0.0.10 --port 3389 --timeout 4000
```

Example output:

```
[+] 10.0.0.10:3389 — selected: TLS + CredSSP/NLA required (0x00000003)
```

It reads the `RDP_NEG_RSP`/`RDP_NEG_FAILURE` and decodes the bits (TLS, HYBRID,
HYBRID_EX) and failure codes (e.g. `HYBRID_REQUIRED_BY_SERVER`).

## Tests

```sh
cargo test --release
```

- Unit: the Connection Request is well-formed; neg-response/failure/legacy bytes
  decode correctly.
- Integration: a fake RDP server answers the negotiation and `probe` must read
  the selected protocol over a real socket.

## Credential validation (NLA/CredSSP)

```sh
rdpr0wl check 10.0.0.10 -u 'CORP\\admin' -p Secret123
```

Full **CredSSP** is implemented: X.224 HYBRID negotiation, TLS, and the
TSRequest/NTLMSSP exchange with pubKeyAuth binding. It is proven end to end
against an **in-process CredSSP peer** (`cargo test`): the right password is
accepted, the wrong one rejected. The crypto is anchored to known vectors —
NTLMv2 (NTOWFv2 + NTProofStr) against the official **MS-NLMP** vectors, RC4
against a known vector, and the NTLMSSP seal/sign round-trips and rejects
tampering.

> One honest caveat: the in-process peer shares this implementation's reading of
> the spec, so interop with a **production Windows NLA host** is expected but
> only fully confirmed against a live target — the same final step the SMB
> capture needed `smbclient` for.

## Build

```sh
cargo build --release
```

## License

MIT. See [LICENSE](LICENSE).
