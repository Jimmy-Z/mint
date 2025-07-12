use log::*;

use aead::{KeyInit, OsRng};
use base64::prelude::{BASE64_STANDARD_NO_PAD as BASE64, Engine as _};

pub fn gen_psk<C: KeyInit>() -> String {
	let key = C::generate_key(&mut OsRng);
	BASE64.encode(key.as_slice())
}

pub fn init_cipher<C: KeyInit>(key: &str) -> Option<C> {
	let key = std::fs::read(key)
		.map_err(|e| error!("failed to read \"{}\": {}", key, e))
		.ok()?;
	let key = BASE64
		.decode((&key as &[u8]).trim_ascii())
		.map_err(|e| error!("failed to decode base64: {}", e))
		.ok()?;
	C::new_from_slice(&key)
		.map_err(|e| error!("failed to create cipher: {}", e))
		.ok()
}
