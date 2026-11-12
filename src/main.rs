mod nla;
mod rdp;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::Duration;

/// rdpeek — sonda e validador de RDP (uso autorizado apenas).
#[derive(Parser)]
#[command(name = "rdpeek", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Descobre a postura de segurança (NLA/TLS/RDP) do host.
    Probe {
        target: String,
        #[arg(long, default_value_t = 3389)]
        port: u16,
        #[arg(long, default_value_t = 5000)]
        timeout: u64,
    },
    /// Valida uma credencial via NLA/CredSSP (em desenvolvimento).
    Check {
        target: String,
        #[arg(short, long)]
        user: String,
        #[arg(short, long)]
        pass: String,
        #[arg(long, default_value_t = 3389)]
        port: u16,
        #[arg(long, default_value_t = 5000)]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Probe { target, port, timeout } => {
            let to = Duration::from_millis(timeout);
            eprintln!("[*] rdpeek probe {target}:{port}");
            match rdp::probe(&target, port, to).await {
                Ok(p) => println!("[+] {target}:{port} — {}", rdp::describe(&p)),
                Err(e) => eprintln!("[!] {target}:{port} — {e}"),
            }
        }
        Cmd::Check { target, user, pass, port, timeout } => {
            let to = Duration::from_millis(timeout);
            match nla::check(&target, port, &user, &pass, to).await {
                Ok(true) => println!("[+] VÁLIDO {user}:{pass}"),
                Ok(false) => println!("[-] inválido {user}"),
                Err(e) => eprintln!("[!] {e}"),
            }
        }
    }
    Ok(())
}
