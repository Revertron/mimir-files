use std::collections::HashMap;
use std::io::{self, Write};

pub type TlvMap = HashMap<u8, Vec<u8>>;

/// Write a varint (up to 4 bytes, 28 bits) using protobuf-style encoding.
pub fn write_varint<W: Write>(w: &mut W, mut value: u32) -> io::Result<()> {
    for _ in 0..4 {
        let mut b = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        w.write_all(&[b])?;
        if value == 0 {
            return Ok(());
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

/// Read a varint from a byte slice at offset, returns (value, bytes_consumed).
fn read_varint_from_bytes(data: &[u8], offset: usize) -> io::Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    for i in 0..4 {
        if offset + i >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "varint: unexpected end of data"));
        }
        let b = data[offset + i];
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

/// Write a single TLV field.
pub fn write_tlv<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    write_varint(w, value.len() as u32)?;
    if !value.is_empty() {
        w.write_all(value)?;
    }
    Ok(())
}

/// Parse a TLV-encoded payload into a map of tag -> value.
pub fn parse_tlvs(payload: &[u8]) -> io::Result<TlvMap> {
    let mut result = TlvMap::new();
    let mut offset = 0;

    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;

        let (length, consumed) = read_varint_from_bytes(payload, offset)?;
        offset += consumed;

        let length = length as usize;
        if offset + length > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tag 0x{:02X} length {} exceeds payload bounds", tag, length),
            ));
        }
        let value = payload[offset..offset + length].to_vec();
        offset += length;

        result.insert(tag, value);
    }

    Ok(result)
}

// --- Extraction helpers ---

pub fn tlv_get_bytes(m: &TlvMap, tag: u8, expected_size: usize) -> Result<&[u8], String> {
    let val = m.get(&tag).ok_or_else(|| format!("missing required tag 0x{:02X}", tag))?;
    if expected_size > 0 && val.len() != expected_size {
        return Err(format!("tag 0x{:02X}: expected {} bytes, got {}", tag, expected_size, val.len()));
    }
    Ok(val)
}

pub fn tlv_get_u64(m: &TlvMap, tag: u8) -> Result<u64, String> {
    let val = tlv_get_bytes(m, tag, 8)?;
    Ok(u64::from_be_bytes(val.try_into().unwrap()))
}

pub fn tlv_get_i64(m: &TlvMap, tag: u8) -> Result<i64, String> {
    tlv_get_u64(m, tag).map(|v| v as i64)
}

pub fn tlv_get_u32(m: &TlvMap, tag: u8) -> Result<u32, String> {
    let val = tlv_get_bytes(m, tag, 4)?;
    Ok(u32::from_be_bytes(val.try_into().unwrap()))
}

// --- Encoding helpers ---

pub fn tlv_encode_bytes<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    write_tlv(w, tag, value)
}

pub fn tlv_encode_u64<W: Write>(w: &mut W, tag: u8, value: u64) -> io::Result<()> {
    write_tlv(w, tag, &value.to_be_bytes())
}

pub fn tlv_encode_i64<W: Write>(w: &mut W, tag: u8, value: i64) -> io::Result<()> {
    tlv_encode_u64(w, tag, value as u64)
}

#[allow(dead_code)]
pub fn tlv_encode_u32<W: Write>(w: &mut W, tag: u8, value: u32) -> io::Result<()> {
    write_tlv(w, tag, &value.to_be_bytes())
}

/// Build a complete TLV payload using a closure that writes TLV fields.
pub fn build_tlv_payload<F>(build_fn: F) -> io::Result<Vec<u8>>
where
    F: FnOnce(&mut Vec<u8>) -> io::Result<()>,
{
    let mut buf = Vec::new();
    build_fn(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u32, 1, 127, 128, 16383, 16384, 0x0FFFFFFF] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).unwrap();
            let (decoded, consumed) = read_varint_from_bytes(&buf, 0).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_tlv_roundtrip() {
        let mut buf = Vec::new();
        tlv_encode_u64(&mut buf, TAG_TOTAL_SIZE, 42).unwrap();
        tlv_encode_i64(&mut buf, TAG_MESSAGE_GUID, 12345).unwrap();
        tlv_encode_bytes(&mut buf, TAG_FILE_HASH, &[0xAB; 32]).unwrap();

        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(tlv_get_u64(&map, TAG_TOTAL_SIZE).unwrap(), 42);
        assert_eq!(tlv_get_i64(&map, TAG_MESSAGE_GUID).unwrap(), 12345);
        assert_eq!(tlv_get_bytes(&map, TAG_FILE_HASH, 32).unwrap(), &[0xAB; 32]);
    }

    #[test]
    fn test_parse_empty() {
        let map = parse_tlvs(&[]).unwrap();
        assert!(map.is_empty());
    }
}
