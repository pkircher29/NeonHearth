use lattice_sensor::active::{ActiveError, render_ip_san};

#[test]
fn ip_sans_use_canonical_address_rendering_and_reject_invalid_lengths() {
    assert_eq!(render_ip_san(&[192, 168, 1, 9]).unwrap(), "192.168.1.9");
    assert_eq!(
        render_ip_san(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
        "fe80::1"
    );
    assert_eq!(render_ip_san(&[1, 2, 3]).unwrap_err(), ActiveError::Network);
}
