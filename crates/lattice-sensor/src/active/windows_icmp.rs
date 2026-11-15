use super::*;
use std::ptr::{null, null_mut};
use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, NetworkManagement::IpHelper::*};

pub(super) async fn echo(
    binding: AuthorizedBinding,
    timeout: Duration,
) -> Result<TransportResponse, ActiveError> {
    tokio::task::spawn_blocking(move || {
        let (IpAddr::V4(source), IpAddr::V4(target)) = (binding.source, binding.target) else {
            return Err(ActiveError::Unavailable);
        };
        // The IP Helper echo API runs without a raw socket or capture driver.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ActiveError::Unavailable);
        }
        let payload = b"NeonHearth";
        let mut response = [0u64; 128];
        let count = unsafe {
            IcmpSendEcho2Ex(
                handle,
                null_mut(),
                None,
                null(),
                u32::from_ne_bytes(source.octets()),
                u32::from_ne_bytes(target.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                null(),
                response.as_mut_ptr().cast(),
                std::mem::size_of_val(&response) as u32,
                timeout.as_millis().clamp(1, 3000) as u32,
            )
        };
        unsafe { IcmpCloseHandle(handle) };
        if count == 0 {
            return Ok(TransportResponse::Timeout);
        }
        let reply = unsafe { &*response.as_ptr().cast::<ICMP_ECHO_REPLY>() };
        if reply.Status != 0 || reply.Address != u32::from_ne_bytes(target.octets()) {
            return Err(ActiveError::Correlation);
        }
        Ok(TransportResponse::Success(vec![(
            "latency_ms".into(),
            reply.RoundTripTime.to_string(),
        )]))
    })
    .await
    .map_err(|_| ActiveError::Internal)?
}
