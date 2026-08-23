use lattice_sensor::active::{ActiveError, recv_bounded_datagram};
use tokio::net::UdpSocket;

#[tokio::test]
async fn shared_udp_receive_contract_rejects_cap_plus_one_instead_of_truncating() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&[0x55; 65], receiver.local_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        recv_bounded_datagram(&receiver, 64).await.unwrap_err(),
        ActiveError::ResponseLimit
    );
    sender
        .send_to(&[0x55; 64], receiver.local_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        recv_bounded_datagram(&receiver, 64).await.unwrap().0.len(),
        64
    );
}
