use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::*;

use chacha20poly1305::ChaCha20Poly1305 as Cipher;
use tokio::net::{TcpListener, TcpStream};

mod proto;
mod key;
mod fake;

use proto::*;
use key::*;

#[derive(Parser)]
struct Args {
	#[command(subcommand)]
	cmd: Cmds,
}

#[derive(Subcommand)]
enum Cmds {
	#[command(alias = "s")]
	Server {
		/// PSK file path
		#[arg(short = 'k', default_value = "psk")]
		psk: String,

		#[arg(short, default_value = "127.0.0.1:8080")]
		listen: String,

		#[arg(short)]
		fake_header: Option<String>,
	},

	#[command(alias = "c")]
	Client {
		/// PSK file path
		#[arg(short = 'k', default_value = "psk")]
		psk: String,

		#[arg(short, default_value = "127.0.0.1:1080")]
		listen: String,

		#[arg(short, default_value = "127.0.0.1:8080")]
		server: String,

		#[arg(short)]
		fake_header: Option<String>,
	},

	/// generate PSK
	GenPSK,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let args = Args::parse();

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

	match &args.cmd {
		Cmds::Server { psk, listen, fake_header } => {
			ls_run(server(psk, listen)).await;
		}
		Cmds::Client { psk, listen, server, fake_header } => {
			ls_run(client(psk, listen, server)).await;
		}
		Cmds::GenPSK => {
			println!("{}", gen_psk::<Cipher>());
		}
	}
}

// runs in local set
async fn ls_run(f: impl Future) {
	let ls = tokio::task::LocalSet::new();
	ls.run_until(f).await;
}

async fn server(key: &str, listen: &str) -> Option<()> {
	let header = fake_resp_header();
	let cipher: Cipher = init_cipher(key)?;

	let l = TcpListener::bind(listen).await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

	while let Ok((mut s, r_addr)) = l.accept().await {
		let cipher = cipher.clone();
		tokio::task::spawn_local(async move {
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
			duplex(&cipher, &mut u, &mut s).await;
		});
	}

	Some(())
}

async fn client(key: &str, listen: &str, upstream: &str) -> Option<()> {
	let header = fake_req_header();
	let cipher: Cipher = init_cipher(key)?;

	let upstream: SocketAddr = upstream.parse().unwrap();
	info!("server addr: {}", upstream);

	let l = TcpListener::bind(listen).await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

	while let Ok((mut s, r_addr)) = l.accept().await {
		let cipher = cipher.clone();
		tokio::task::spawn_local(async move {
			let mut buf = BytesMut::with_capacity(0x500);
			let Some((addr, port)) = socks5::server_handshake(&mut s).await else {
				return;
			};
			info!("{} -> {}:{}", r_addr, addr, port);
			let Ok(mut u) = TcpStream::connect(upstream)
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
			duplex(&cipher, &mut s, &mut u).await;
		});
	}

	Some(())
}
