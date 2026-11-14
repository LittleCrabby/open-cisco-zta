use crate::dataplane::stream::H2TunnelStream;
use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Encodes a QUIC variable-length integer (RFC 9000 Section 16) into `buf`.
pub fn put_quic_varint(buf: &mut BytesMut, val: u64) -> Result<()> {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16_384 {
        buf.put_u16((val as u16) | 0x4000);
    } else if val < 1_073_741_824 {
        buf.put_u32((val as u32) | 0x8000_0000);
    } else if val < 4_611_686_018_427_387_904 {
        buf.put_u64(val | 0xc000_0000_0000_0000);
    } else {
        bail!("Value {} exceeds maximum 62-bit QUIC varint", val);
    }
    Ok(())
}

/// Peeks a QUIC variable-length integer (RFC 9000 Section 16) from the start of `slice`,
/// returning `Some((value, encoded_byte_len))` if enough bytes are available, or `None` if incomplete.
pub fn peek_quic_varint(slice: &[u8]) -> Option<(u64, usize)> {
    let first = *slice.first()?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if slice.len() < len {
        return None;
    }
    let val = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let mut b = [0u8; 2];
            b.copy_from_slice(&slice[..2]);
            b[0] &= 0x3f;
            u16::from_be_bytes(b) as u64
        }
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&slice[..4]);
            b[0] &= 0x3f;
            u32::from_be_bytes(b) as u64
        }
        8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&slice[..8]);
            b[0] &= 0x3f;
            u64::from_be_bytes(b)
        }
        _ => unreachable!(),
    };
    Some((val, len))
}

/// Encodes a raw UDP payload into an RFC 9297 / RFC 9298 HTTP `DATAGRAM` capsule
/// (`Capsule Type = 0x00`, `Capsule Length = varint(1 + payload.len())`, `Context ID = 0x00`, `Payload`).
pub fn encode_udp_capsule(payload: &[u8]) -> Result<Bytes> {
    let capsule_len = (1 + payload.len()) as u64;
    let mut buf = BytesMut::with_capacity(10 + payload.len());
    // Capsule Type = 0x00 (DATAGRAM)
    buf.put_u8(0x00);
    // Capsule Length = 1 (Context ID) + payload.len()
    put_quic_varint(&mut buf, capsule_len)?;
    // Context ID = 0x00 (UDP payload)
    buf.put_u8(0x00);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

/// Attempts to decode the next UDP `DATAGRAM` capsule (Context ID 0) from `buf`.
/// Unknown capsule types or non-zero Context IDs are skipped per RFC 9297 / RFC 9298.
/// Returns `Ok(None)` if `buf` does not yet contain a complete capsule.
pub fn try_decode_udp_capsule(buf: &mut BytesMut) -> Result<Option<Bytes>> {
    loop {
        if buf.is_empty() {
            return Ok(None);
        }
        let (capsule_type, type_len) = match peek_quic_varint(buf) {
            Some(v) => v,
            None => return Ok(None),
        };
        let (capsule_len, len_len) = match peek_quic_varint(&buf[type_len..]) {
            Some(v) => v,
            None => return Ok(None),
        };
        // Guard against unreasonable capsule sizes (> 64 KiB for UDP datagrams)
        if capsule_len > 65_536 {
            bail!(
                "Invalid HTTP datagram capsule length {} (type {})",
                capsule_len,
                capsule_type
            );
        }
        let header_len = type_len + len_len;
        let total_len = header_len + (capsule_len as usize);
        if buf.len() < total_len {
            return Ok(None);
        }

        buf.advance(header_len);
        let mut body = buf.split_to(capsule_len as usize);

        if capsule_type == 0x00 {
            let (context_id, ctx_len) = match peek_quic_varint(&body) {
                Some(v) => v,
                None => bail!("Malformed empty DATAGRAM capsule missing Context ID"),
            };
            body.advance(ctx_len);
            if context_id == 0x00 {
                return Ok(Some(body.freeze()));
            } else {
                tracing::debug!(
                    "Ignoring DATAGRAM capsule with non-zero Context ID {}",
                    context_id
                );
            }
        } else {
            tracing::debug!("Ignoring unknown HTTP capsule type {}", capsule_type);
        }
    }
}

/// High-level wrapper around an `H2TunnelStream` negotiated with `CONNECT-UDP`
/// that frames and deframes UDP datagrams using RFC 9297 / RFC 9298 HTTP Capsules.
pub struct H2UdpStream {
    inner: H2TunnelStream,
    read_buf: BytesMut,
}

impl H2UdpStream {
    pub fn new(inner: H2TunnelStream) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(8192),
        }
    }

    pub async fn send_datagram(&mut self, payload: &[u8]) -> Result<()> {
        let capsule = encode_udp_capsule(payload)?;
        self.inner
            .write_all(&capsule)
            .await
            .context("Failed to write UDP capsule to H2 stream")?;
        Ok(())
    }

    pub async fn recv_datagram(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(datagram) = try_decode_udp_capsule(&mut self.read_buf)? {
                return Ok(Some(datagram));
            }
            let n = self
                .inner
                .read_buf(&mut self.read_buf)
                .await
                .context("Failed to read UDP capsule from H2 stream")?;
            if n == 0 {
                return Ok(None);
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let _ = self.inner.shutdown().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_varint_roundtrip() {
        for &(val, expected_len) in &[
            (0u64, 1usize),
            (37, 1),
            (63, 1),
            (64, 2),
            (15293, 2),
            (16383, 2),
            (16384, 4),
            (494_878_333, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (151_288_809_941_952_652, 8),
        ] {
            let mut buf = BytesMut::new();
            put_quic_varint(&mut buf, val).unwrap();
            assert_eq!(buf.len(), expected_len);
            let (decoded, len) = peek_quic_varint(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(len, expected_len);
        }
    }

    #[test]
    fn test_udp_capsule_small_and_medium_roundtrip() {
        // Small payload (< 63 bytes -> 1-byte length varint)
        let small_payload = b"hello kerberos kdc";
        let capsule = encode_udp_capsule(small_payload).unwrap();
        assert_eq!(capsule[0], 0x00); // Capsule Type = DATAGRAM (0)
        assert_eq!(capsule[1], (1 + small_payload.len()) as u8); // 1-byte varint length
        assert_eq!(capsule[2], 0x00); // Context ID = 0
        assert_eq!(&capsule[3..], small_payload);

        let mut rx_buf = BytesMut::from(&capsule[..]);
        let decoded = try_decode_udp_capsule(&mut rx_buf).unwrap().unwrap();
        assert_eq!(&decoded[..], small_payload);
        assert!(rx_buf.is_empty());

        // Medium payload (e.g., 1400-byte Kerberos ticket -> 2-byte length varint)
        let med_payload = vec![0xab; 1400];
        let med_capsule = encode_udp_capsule(&med_payload).unwrap();
        assert_eq!(med_capsule[0], 0x00);
        // 1401 = 0x0579 -> with 0x4000 prefix = 0x45, 0x79
        assert_eq!(med_capsule[1], 0x45);
        assert_eq!(med_capsule[2], 0x79);
        assert_eq!(med_capsule[3], 0x00);

        // Test fragmented arrival + coalesced capsules
        let mut stream_buf = BytesMut::new();
        stream_buf.extend_from_slice(&med_capsule[..10]);
        assert!(try_decode_udp_capsule(&mut stream_buf).unwrap().is_none());
        stream_buf.extend_from_slice(&med_capsule[10..]);
        stream_buf.extend_from_slice(&capsule);

        let d1 = try_decode_udp_capsule(&mut stream_buf).unwrap().unwrap();
        assert_eq!(&d1[..], &med_payload[..]);
        let d2 = try_decode_udp_capsule(&mut stream_buf).unwrap().unwrap();
        assert_eq!(&d2[..], small_payload);
        assert!(try_decode_udp_capsule(&mut stream_buf).unwrap().is_none());
    }
}
