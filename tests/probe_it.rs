//! Fake RDP server that answers the X.224 negotiation, proving probe() reads
//! the selected security protocol end to end over a real socket.
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn cc_selecting(protocol: u32) -> Vec<u8> {
    let mut r = vec![0x03, 0x00, 0x00, 0x13]; // TPKT len 19
    r.extend_from_slice(&[0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00]); // X224 CC
    r.push(0x02); // RDP_NEG_RSP
    r.push(0x00); // flags
    r.extend_from_slice(&8u16.to_le_bytes()); // length
    r.extend_from_slice(&protocol.to_le_bytes());
    r
}

async fn fake_server(protocol: u32) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await; // consume the Connection Request
            let _ = s.write_all(&cc_selecting(protocol)).await;
            let _ = s.flush().await;
        }
    });
    port
}

#[tokio::test]
async fn probe_detects_nla() {
    let port = fake_server(rdpr0wl::rdp::PROTOCOL_SSL | rdpr0wl::rdp::PROTOCOL_HYBRID).await;
    let p = rdpr0wl::rdp::probe("127.0.0.1", port, Duration::from_secs(3))
        .await
        .expect("probe completes");
    assert_eq!(p, rdpr0wl::rdp::Posture::Selected(0x03));
    assert!(rdpr0wl::rdp::describe(&p).contains("CredSSP/NLA required"));
}

#[tokio::test]
async fn probe_detects_plain_rdp() {
    let port = fake_server(rdpr0wl::rdp::PROTOCOL_RDP).await;
    let p = rdpr0wl::rdp::probe("127.0.0.1", port, Duration::from_secs(3))
        .await
        .expect("probe completes");
    assert_eq!(p, rdpr0wl::rdp::Posture::Selected(0));
    assert!(rdpr0wl::rdp::describe(&p).contains("insecure"));
}
