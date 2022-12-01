/// pads a byte slice message according to pkcs7
/// block_size is in bytes
pub fn pkcs7_padder(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = Vec::from(message);
    let msg_len = message.len();

    let remainder = msg_len % block_size;
    let amount = block_size - remainder;

    let mut padding = vec![amount as u8; amount];

    padded.append(&mut padding);
    padded
}

pub fn pkcs7_validate_padding(message: &[u8], block_size: usize) -> bool {
    let msg_len = message.len();
    let mut message_iter = message.iter();

    if msg_len % block_size == 0 {
        let last_byte = if let Some(last_byte) = message_iter.next_back() {
            *last_byte
        } else {
            return false;
        };

        if last_byte > (block_size as u8) {
            return false;
        };

        let mut remaining_bytes = last_byte - 1;
        while remaining_bytes > 0 {
            if let Some(next_byte) = message_iter.next_back() {
                if *next_byte != last_byte {
                    return false;
                }
            } else {
                return false;
            }
            remaining_bytes -= 1;
        }
    } else {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_world() {
        let hello_world = b"\x48\x65\x6C\x6C\x6F\x2C\x20\x57\x6F\x72\x6C\x64\x21";
        let pad_to_16 = pkcs7_padder(hello_world, 16);
        let expected_pad_16 = b"\x48\x65\x6C\x6C\x6F\x2C\x20\x57\x6F\x72\x6C\x64\x21\x03\x03\x03";
        assert_eq!(pad_to_16, expected_pad_16);
        assert!(pkcs7_validate_padding(expected_pad_16, 16))
    }
}
