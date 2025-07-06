use std::sync::Arc;

use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::*;

use aead::{AeadCore, AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305 as Cipher;
use tokio::net::{TcpListener, TcpStream};

mod proto;
mod socks5;
mod utils;

use proto::*;
use utils::*;

#[derive(Parser)]
struct Args {
	#[command(subcommand)]
	cmd: Cmds,
}

#[derive(Subcommand)]
enum Cmds {
	#[command(alias = "s")]
	Server {
		#[arg(long, short = 'k', default_value = "psk")]
		psk: String,
	},

	#[command(alias = "c")]
	Client {
		#[arg(long, short, default_value = "127.0.0.1:8080")]
		upstream: String,

		#[arg(long, short = 'k', default_value = "psk")]
		psk: String,
	},

	/// generate PSK
	GenPSK,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let args = Args::parse();

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

	match &args.cmd {
		Cmds::Server { psk } => {
			server(psk).await;
		}
		Cmds::Client { psk, upstream } => {
			client(psk, upstream).await;
		}
		Cmds::GenPSK => {
			println!("{}", gen_psk::<Cipher>());
		}
	}
}

async fn server(key: &str) -> Option<()> {
	let header = fake_resp_header();
	let cipher: Cipher = init_cipher(key)?;

	let l = TcpListener::bind("0.0.0.0:8080").await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

	while let Ok((mut s, r_addr)) = l.accept().await {
		let cipher = cipher.clone();
		tokio::spawn(async move {
			let mut buf = BytesMut::with_capacity(0x500);
			let Some((addr, port)) = server_handshake(&mut s, &cipher, &mut buf, &header).await
			else {
				return;
			};
			info!("{} -> {}:{}", r_addr, addr, port);
			let Ok(mut u) = TcpStream::connect(&format!("{}:{}", addr, port))
				.await
				.map_err(|e| error!("error connecting to upstream: {}", e))
			else {
				return;
			};
			let _ = tokio::io::copy_bidirectional(&mut s, &mut u).await;
		});
	}

	Some(())
}

async fn client(key: &str, upstream: &str) -> Option<()> {
	let header = fake_req_header();
	let cipher: Cipher = init_cipher(key)?;

	let l = TcpListener::bind("0.0.0.0:1080").await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

	while let Ok((mut s, r_addr)) = l.accept().await {
		let cipher = cipher.clone();
		let upstream = upstream.to_string();
		tokio::spawn(async move {
			let mut buf = BytesMut::with_capacity(0x500);
			let Some((addr, port)) = socks5::server_handshake(&mut s).await else {
				return;
			};
			info!("{} -> {}:{}", r_addr, addr, port);
			let Ok(mut u) = TcpStream::connect(&upstream)
				.await
				.map_err(|e| error!("error connecting to upstream: {}", e))
			else {
				return;
			};
			let Some(()) =
				client_handshake(&mut u, &cipher, &mut buf, &addr.to_string(), port, &header).await
			else {
				return;
			};
			let _ = tokio::io::copy_bidirectional(&mut s, &mut u).await;
		});
	}

	Some(())
}
