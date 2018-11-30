use sawtooth_sdk::consensus::{engine::*};

const WC_DELIM_CHAR : u8 = '#' as u8; //0x23

pub fn to_hex_string(bytes: &Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
    .collect();
    strs.join("")
}

pub fn blockid_to_hex_string(blockid: BlockId) -> String {
    let blockid_vec = Vec::from(blockid);
    to_hex_string(&blockid_vec)
}

pub fn payload_to_wc_and_sig(payload: &Vec<u8>) 
    -> (String, String) {
    let delim_index = payload.iter().position(|&i| i == WC_DELIM_CHAR).unwrap();
    let payload_parts = payload.split_at(delim_index + 1);
    let mut wait_certificate = String::from_utf8(payload_parts.0.to_vec()).unwrap();
    wait_certificate.pop(); // remove trailing delim
    let wait_certificate_sig = String::from_utf8(payload_parts.1.to_vec()).unwrap();
    (wait_certificate, wait_certificate_sig)
}
