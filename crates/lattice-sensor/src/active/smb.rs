//! SMB2/3 negotiation only: no SMB1, authentication, session, or share access.
use super::{ActiveError, TransportResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) async fn negotiate(stream: &mut tokio::net::TcpStream) -> Result<TransportResponse, ActiveError> {
    let mut request = vec![0u8; 108];
    request[..4].copy_from_slice(b"\xfeSMB");
    request[4..6].copy_from_slice(&64u16.to_le_bytes());
    request[14..16].copy_from_slice(&1u16.to_le_bytes());
    getrandom::fill(&mut request[24..32]).map_err(|_| ActiveError::Internal)?;
    request[64..66].copy_from_slice(&36u16.to_le_bytes());
    request[66..68].copy_from_slice(&4u16.to_le_bytes());
    request[68..70].copy_from_slice(&1u16.to_le_bytes());
    getrandom::fill(&mut request[76..92]).map_err(|_| ActiveError::Internal)?;
    for (index, dialect) in [0x0202u16, 0x0210, 0x0300, 0x0302].iter().enumerate() {
        request[100 + index * 2..102 + index * 2].copy_from_slice(&dialect.to_le_bytes());
    }
    let message_id: [u8; 8] = request[24..32].try_into().map_err(|_| ActiveError::Internal)?;
    let mut wire = (request.len() as u32).to_be_bytes().to_vec();
    wire.extend(request);
    stream.write_all(&wire).await.map_err(|_| ActiveError::Network)?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| ActiveError::Network)?;
    let size = u32::from_be_bytes(header) as usize;
    if header[0] != 0 || !(128..=16_384).contains(&size) { return Err(ActiveError::ResponseLimit); }
    let mut response = vec![0; size];
    stream.read_exact(&mut response).await.map_err(|_| ActiveError::Network)?;
    parse(&response, message_id).map(TransportResponse::Success)
}

fn parse(b: &[u8], message_id: [u8; 8]) -> Result<Vec<(String, String)>, ActiveError> {
    if b.len() < 128 || b.len() > 16_384 || &b[..4] != b"\xfeSMB"
        || b[4..6] != 64u16.to_le_bytes() || b[8..12] != [0; 4]
        || b[12..14] != [0; 2] || b[16] & 1 == 0 || b[20..24] != [0; 4]
        || b[24..32] != message_id || b[64..66] != 65u16.to_le_bytes() {
        return Err(ActiveError::Correlation);
    }
    let dialect = u16::from_le_bytes([b[68], b[69]]);
    let dialect = match dialect { 0x0202 => "SMB 2.0.2", 0x0210 => "SMB 2.1", 0x0300 => "SMB 3.0", 0x0302 => "SMB 3.0.2", _ => return Err(ActiveError::Correlation) };
    let offset = u16::from_le_bytes([b[120], b[121]]) as usize;
    let length = u16::from_le_bytes([b[122], b[123]]) as usize;
    if length > 0 && (offset < 128 || offset + length > b.len()) { return Err(ActiveError::ResponseLimit); }
    Ok(vec![("dialect".into(), dialect.into()),
        ("signing_required".into(), (b[66] & 2 != 0).to_string()),
        ("server_guid".into(), b[72..88].iter().map(|v| format!("{v:02x}")).collect())])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_smb_response_correlation_and_bounds() {
        let mut b = vec![0; 128]; b[..4].copy_from_slice(b"\xfeSMB"); b[4] = 64;
        b[16] = 1; b[64] = 65; b[66] = 3; b[68..70].copy_from_slice(&0x0302u16.to_le_bytes());
        assert!(parse(&b, [0; 8]).unwrap().contains(&("signing_required".into(), "true".into())));
        b[24] = 1; assert_eq!(parse(&b, [0; 8]), Err(ActiveError::Correlation)); b[24] = 0;
        b[122] = 5; assert_eq!(parse(&b, [0; 8]), Err(ActiveError::ResponseLimit));
        for end in 0..128 { assert!(parse(&b[..end], [0; 8]).is_err()); }
    }
}
