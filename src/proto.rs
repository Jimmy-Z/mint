/*
* general
	* it's very much like SOCKS5.
	* but handshake is encrypted with a PSK using ChaCha20Poly1305.
	* once handshake is done, it's plain TCP just like SOCKS.
	* handshake message (including padding) should not exceed 1280(0x500) bytes
	* so it always arrive in one packet.
	* message MUST be written in a single write call.
* message format
	* a fake header, ends with double CRLF
	* to fake some protocols, for reasons
	* 12 bytes random nonce
	* 2 bytes _len_ of the encrypted part
	* it's xor'ed with (the last two bytes of) nonce to make it look random
	* not encrypted but authenticated as associate data
	* encrypted payload
	* request or response
	* padding
* request:
	* 1 byte VER, 0
	* 1 byte length of the host
	* host
	* 2 bytes dest port
* response:
	* 1 byte reply, 0 means succeed
*/

use aead::generic_array::GenericArray;
use bytes::{BufMut, Bytes, BytesMut, buf};
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, aead::OsRng};
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// to do: don't hard encode
const NONCE_LEN: usize = 12;
const OVERHEAD_LEN: usize = 16;

const EOH: &[u8] = b"\r\n\r\n";

const VER: u8 = 0;
const REP_OK: u8 = 0;

pub fn fake_req_header() -> &'static [u8] {
	b"POST /upload HTTP/1.1\r\nHOST: www.apple.com\r\n\r\n"
}

pub fn fake_resp_header() -> &'static [u8] {
	b"HTTP/1.1 200 OK\r\n\r\n"
}

pub fn nonce_size<T: AeadCore>() -> usize {
	// T::NonceSize::len()
	unimplemented!()
}

pub async fn client_handshake<
	T: AsyncRead + AsyncWrite + Unpin,
	C: KeyInit + AeadCore + AeadInPlace,
>(
	io: &mut T,
	// key: &[u8],
	cipher: &C,
	buf: &mut BytesMut,
	host: &str,
	port: u16,
	header: &[u8],
) -> Option<()> {
	buf.clear();
	write_msg(buf, cipher, header, &Req(host, port));
	io.write_all(buf)
		.await
		.map_err(|e| debug!("handshake error writing: {}", e))
		.ok()?;

	buf.clear();
	io.read_buf(buf)
		.await
		.map_err(|e| debug!("handshake error reading: {}", e))
		.ok()?;
	let Some(resp): Option<Resp> = read_msg(buf, cipher) else {
		return None;
	};

	if resp.0 != REP_OK {
		debug!("server replies 0x{:02x}, unexpected", resp.0);
		return None;
	}

	// debug!("buf capacity: {}", buf.capacity());
	Some(())
}

pub async fn server_handshake<
	T: AsyncRead + AsyncWrite + Unpin,
	C: KeyInit + AeadCore + AeadInPlace,
>(
	io: &mut T,
	// key: &[u8],
	cipher: &C,
	buf: &mut BytesMut,
	header: &[u8],
) -> Option<(String, u16)> {
	buf.clear();
	io.read_buf(buf)
		.await
		.map_err(|e| debug!("handshake error reading: {}", e))
		.ok()?;
	let Some(req): Option<Req> = read_msg(buf, cipher) else {
		return None;
	};

	let host = req.0.to_owned();
	let port = req.1;

	buf.clear();
	write_msg(buf, cipher, header, &Resp(REP_OK));
	io.write_all(buf)
		.await
		.map_err(|e| debug!("handshake error writing: {}", e))
		.ok()?;

	// debug!("buf capacity: {}", buf.capacity());
	Some((host, port))
}

// can't be implemented on BufMut since we want encrypt in place
fn write_msg<'a, C: AeadCore + AeadInPlace>(
	buf: &mut BytesMut,
	// key: &[u8],
	cipher: &C,
	header: &[u8],
	payload: &impl Payload<'a>,
) {
	buf.put_slice(header);

	let nonce = C::generate_nonce(&mut OsRng);
	buf.put_slice(&nonce);

	let len = (payload.len() + OVERHEAD_LEN) as u16;
	buf.put_u16(len);
	let payload_offset = buf.len();

	payload.write(&mut *buf);

	let mut payload = buf.split_off(payload_offset);

	// let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
	cipher
		.encrypt_in_place(&nonce, &buf[payload_offset - 2..], &mut payload)
		.unwrap();

	buf.unsplit(payload);
}

fn read_msg<'a, C: AeadCore + AeadInPlace, T: Payload<'a>>(
	buf: &'a mut BytesMut,
	// key: &[u8],
	cipher: &C,
) -> Option<T> {
	debug!("read: {}", buf.len());
	let Some(eoh) = buf.as_ref().windows(EOH.len()).position(|w| w == EOH) else {
		error!("End of Header not found, unexpected");
		return None;
	};
	debug!("eoh: {}", eoh);

	let nonce_offset = eoh + EOH.len();

	let len_offset = nonce_offset + NONCE_LEN;
	let len = u16::from_be_bytes(buf[len_offset..len_offset + 2].try_into().unwrap());

	// check length
	let payload_offset = len_offset + 2;
	let mut payload = buf.split_off(payload_offset);
	// let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
	if let Err(e) = cipher.decrypt_in_place(
		&GenericArray::from_slice(&buf[nonce_offset..nonce_offset + NONCE_LEN]),
		&buf[len_offset..len_offset + 2],
		&mut payload,
	) {
		error!("failed to decrypt message: {}", e);
		return None;
	}
	buf.unsplit(payload);

	Payload::read(&buf[payload_offset..])
}

trait Payload<'a>: Sized {
	fn len(&self) -> usize;
	fn write(&self, buf: impl BufMut);
	fn read(buf: &'a [u8]) -> Option<Self>;
}

#[derive(Debug, PartialEq, Eq)]
struct Req<'a>(&'a str, u16);

#[derive(Debug, PartialEq, Eq)]
struct Resp(u8);

impl<'a> Payload<'a> for Req<'a> {
	fn len(&self) -> usize {
		1 + self.0.len() + 2
	}
	fn write(&self, mut buf: impl BufMut) {
		buf.put_u8(VER);
		buf.put_u8(self.0.len() as u8);
		buf.put_slice(self.0.as_bytes());
		buf.put_u16(self.1);
	}
	fn read(buf: &'a [u8]) -> Option<Self> {
		let ver = buf[0];
		if ver != VER {
			error!("invalid ver: 0x{:02x}", ver);
			return None;
		}
		let len = buf[1];
		if buf.len() != 2 + len as usize + 2 {
			error!(
				"invalid request length: {} != {}",
				buf.len(),
				2 + len as usize + 2
			);
			return None;
		}
		let Ok(host) = str::from_utf8(&buf[2..2 + len as usize]) else {
			error!("invalid utf8 in host");
			return None;
		};
		let port = u16::from_be_bytes(buf[2 + len as usize..].try_into().unwrap());
		Some(Req(host, port))
	}
}

impl<'a> Payload<'a> for Resp {
	fn len(&self) -> usize {
		1
	}
	fn write(&self, mut buf: impl BufMut) {
		buf.put_u8(self.0);
	}
	fn read(buf: &'a [u8]) -> Option<Self> {
		if buf.len() != 1 {
			error!("invalid response length");
			return None;
		}
		Some(Resp(buf[0]))
	}
}

#[cfg(test)]
mod test {
	use std::fmt::Write;

	use bytes::BytesMut;
	use chacha20poly1305::{
		AeadCore, ChaCha20Poly1305, KeyInit, aead::OsRng,
	};

	use super::*;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	#[test]
	fn test_payload() {
		init();

		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		println!("key len: {}", key.len());
		let cipher = ChaCha20Poly1305::new(&key);
		let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
		println!("nonce len: {}", nonce.len());
		assert_eq!(nonce.len(), NONCE_LEN);

		let mut buf = BytesMut::with_capacity(1024);
		let req = Req("example.com", 443);
		write_msg(&mut buf, &cipher, &fake_req_header(), &req);
		let req_r: Req = read_msg(&mut buf, &cipher).unwrap();
		assert_eq!(req, req_r);
	}

	#[tokio::test]
	async fn test_handshake() {
		init();

		let (mut c, mut s) = tokio::io::duplex(0x500);

		let header = &fake_req_header();
		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		let cipher = ChaCha20Poly1305::new(&key);

		tokio::join!(
			async {
				let mut buf = BytesMut::with_capacity(0x500);
				assert_eq!(
					Some(()),
					client_handshake(&mut c, &cipher, &mut buf, "example.com", 443, header).await
				);
			},
			async {
				let mut buf = BytesMut::with_capacity(0x500);
				assert_eq!(
					Some(("example.com".to_owned(), 443)),
					server_handshake(&mut s, &cipher, &mut buf, header).await
				);
			}
		);
	}
}
