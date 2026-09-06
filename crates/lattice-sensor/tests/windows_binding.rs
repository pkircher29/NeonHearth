#![cfg(windows)]

use lattice_sensor::{AuthorizedBinding, SystemInterfaceManager, active};

#[test]
fn windows_interface_pinning_round_trips_the_native_interface_index() {
    let inventory = SystemInterfaceManager.snapshot().unwrap();
    let (interface, source) = inventory
        .interfaces()
        .find_map(|interface| {
            interface
                .addresses
                .iter()
                .find(|address| address.ip.is_ipv4() && address.ip.is_loopback())
                .map(|address| (interface.id, address.ip))
        })
        .expect("Windows must expose its IPv4 loopback interface");
    let socket = std::net::UdpSocket::bind((source, 0)).unwrap();
    active::pin_socket_to_interface(
        &socket,
        AuthorizedBinding {
            source,
            interface_index: interface.get(),
            target: source,
        },
    )
    .expect("Winsock returns IP_UNICAST_IF in host byte order");
}
