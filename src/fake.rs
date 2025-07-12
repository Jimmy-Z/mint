
use std::fs::read_to_string;

pub fn get_fake_header(path: &str) -> Vec<u8> {
	let mut res = String::with_capacity(0x200);
	for l in read_to_string(path).unwrap().lines() {
		let l = l.trim();
		if l.len() == 0 {
			continue;
		}
		res.push_str(l);
		res.push_str("\r\n");
	}
	res.push_str("\r\n");
	res.into_bytes()
}
