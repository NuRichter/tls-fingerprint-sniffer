```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::select;
use tokio::signal;
use tokio::sync::mpsc;

const BUFFER_SIZE: usize = 1500;
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

struct ConnectionState {
    last_seen: Duration,
    packets_sent: u64,
    packets_received: u64,
}

async fn handle_udp_packet(socket: Arc<UdpSocket>, buffer: &[u8], src_addr: &std::net::SocketAddr, dst_addr: &std::net::SocketAddr, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(src_addr) {
        conn_state.last_seen = tokio::time::Instant::now().elapsed();
        conn_state.packets_received += 1;
    } else {
        lock.insert(*src_addr, ConnectionState { last_seen: tokio::time::Instant::now().elapsed(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.send_to(buffer, dst_addr).await.expect("Failed to send UDP packet");
}

async fn handle_tcp_packet(socket: Arc<tokio::net::TcpStream>, buffer: &[u8], state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let peer_addr = match socket.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(&peer_addr) {
        conn_state.last_seen = tokio::time::Instant::now().elapsed();
        conn_state.packets_received += 1;
    } else {
        lock.insert(peer_addr, ConnectionState { last_seen: tokio::time::Instant::now().elapsed(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.write_all(buffer).await.expect("Failed to send TCP packet");
}

async fn process_packets(rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>, udp_socket: Arc<UdpSocket>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    while let Some((buffer, src_addr, dst_addr)) = rx.recv().await {
        if buffer[0] == 17 { // UDP
            handle_udp_packet(udp_socket.clone(), &buffer[8..], &src_addr, &dst_addr, state.clone()).await;
        } else if buffer[0] == 6 { // TCP
            if let Some(mut tcp_stream) = tcp_connections.lock().unwrap().get_mut(&dst_addr) {
                handle_tcp_packet(tcp_stream, &buffer[20..], state.clone()).await;
            }
        }
    }
}

async fn cleanup_connections(state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut lock = state.lock().unwrap();
        let to_remove: Vec<_> = lock.iter().filter(|(_, conn_state)| conn_state.last_seen > Duration::from_secs(60)).map(|(&addr, _)| addr).collect();
        for addr in to_remove {
            tcp_connections.lock().unwrap().remove(&addr);
            lock.remove(&addr);
        }
    }
}

async fn main() {
    let (tx, rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>(BUFFER_SIZE * 2);

    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:9999").await.expect("Failed to bind UDP socket"));
    let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:9998").await.expect("Failed to bind TCP listener");
    let state = Arc::new(Mutex::new(HashMap::new()));
    let tcp_connections = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(process_packets(rx, udp_socket.clone(), tcp_connections.clone(), state.clone()));
    tokio::spawn(cleanup_connections(state.clone(), tcp_connections.clone()));

    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let (tx_clone, tcp_listener_clone, udp_socket_clone) = (tx.clone(), tcp_listener.clone(), udp_socket.clone());
        tokio::spawn(async move {
            loop {
                let mut buffer = vec![0; BUFFER_SIZE];
                match tcp_listener_clone.accept().await {
                    Ok((tcp_stream, src_addr)) => {
                        match udp_socket_clone.recv_from(&mut buffer).await {
                            Ok((nread, dst_addr)) => {
                                if nread > 8 {
                                    tx_clone.send((buffer[..nread].to_vec(), src_addr, dst_addr)).await.expect("Failed to send packet");
                                }
                            },
                            Err(_) => {},
                        }
                    },
                    Err(_) => {},
                }
            }
        });
    }

    signal::ctrl_c().await.expect("Failed to listen for ctrl-c");

}
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::select;
use tokio::signal;
use tokio::sync::mpsc;

const BUFFER_SIZE: usize = 1500;
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

struct ConnectionState {
    last_seen: Duration,
    packets_sent: u64,
    packets_received: u64,
}

async fn handle_udp_packet(socket: Arc<UdpSocket>, buffer: &[u8], src_addr: &std::net::SocketAddr, dst_addr: &std::net::SocketAddr, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(src_addr) {
        conn_state.last_seen = tokio::time::Instant::now().elapsed();
        conn_state.packets_received += 1;
    } else {
        lock.insert(*src_addr, ConnectionState { last_seen: tokio::time::Instant::now().elapsed(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.send_to(buffer, dst_addr).await.expect("Failed to send UDP packet");
}

async fn handle_tcp_packet(socket: Arc<tokio::net::TcpStream>, buffer: &[u8], state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let peer_addr = match socket.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(&peer_addr) {
        conn_state.last_seen = tokio::time::Instant::now().elapsed();
        conn_state.packets_received += 1;
    } else {
        lock.insert(peer_addr, ConnectionState { last_seen: tokio::time::Instant::now().elapsed(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.write_all(buffer).await.expect("Failed to send TCP packet");
}

async fn process_packets(rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>, udp_socket: Arc<UdpSocket>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    while let Some((buffer, src_addr, dst_addr)) = rx.recv().await {
        if buffer[0] == 17 { // UDP
            handle_udp_packet(udp_socket.clone(), &buffer[8..], &src_addr, &dst_addr, state.clone()).await;
        } else if buffer[0] == 6 { // TCP
            if let Some(mut tcp_stream) = tcp_connections.lock().unwrap().get_mut(&dst_addr) {
                handle_tcp_packet(tcp_stream, &buffer[20..], state.clone()).await;
            }
        }
    }
}

async fn cleanup_connections(state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut lock = state.lock().unwrap();
        let to_remove: Vec<_> = lock.iter().filter(|(_, conn_state)| conn_state.last_seen > Duration::from_secs(60)).map(|(&addr, _)| addr).collect();
        for addr in to_remove {
            tcp_connections.lock().unwrap().remove(&addr);
            lock.remove(&addr);
        }
    }
}

async fn main() {
    let (tx, rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>(BUFFER_SIZE * 2);

    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:9999").await.expect("Failed to bind UDP socket"));
    let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:9998").await.expect("Failed to bind TCP listener");
    let state = Arc::new(Mutex::new(HashMap::new()));
    let tcp_connections = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(process_packets(rx, udp_socket.clone(), tcp_connections.clone(), state.clone()));
    tokio::spawn(cleanup_connections(state.clone(), tcp_connections.clone()));

    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let (tx_clone, tcp_listener_clone, udp_socket_clone) = (tx.clone(), tcp_listener.clone(), udp_socket.clone());
        tokio::spawn(async move {
            loop {
                let mut buffer = vec![0; BUFFER_SIZE];
                match tcp_listener_clone.accept().await {
                    Ok((tcp_stream, src_addr)) => {
                        match udp_socket_clone.recv_from(&mut buffer).await {
                            Ok((nread, dst_addr)) => {
                                if nread > 8 {
                                    tx_clone.send((buffer[..nread].to_vec(), src_addr, dst_addr)).await.expect("Failed to send packet");
                                }
                            },
                            Err(_) => {},
                        }
                    },
                    Err(_) => {},
                }
            }
        });
    }

    signal::ctrl_c().await.expect("Failed to listen for ctrl-c");

}
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::select;
use tokio::signal;
use tokio::sync::mpsc;

const BUFFER_SIZE: usize = 1500;
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

struct ConnectionState {
    last_seen: Duration,
    packets_sent: u64,
    packets_received: u64,
}

async fn handle_udp_packet(socket: Arc<UdpSocket>, buffer: &[u8], src_addr: &std::net::SocketAddr, dst_addr: &std::net::SocketAddr, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(src_addr) {
        conn_state.last_seen = tokio::time::Instant::now().elapsed();
        conn_state.packets_received += 1;
    } else {
        lock.insert(*src_addr, ConnectionState { last_seen: tokio::time::Instant::now().elapsed(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.send_to(buffer, dst_addr).await.expect("Failed to send UDP packet");
}

async fn handle_tcp_packet(socket: Arc<tokio::net::TcpStream>, buffer: &[u8], state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let peer_addr = match socket.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(&peer_addr) {
        conn_state.last_seen = tokio::time::Instant::now().elapsed();
        conn_state.packets_received += 1;
    } else {
        lock.insert(peer_addr, ConnectionState { last_seen: tokio::time::Instant::now().elapsed(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.write_all(buffer).await.expect("Failed to send TCP packet");
}

async fn process_packets(rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>, udp_socket: Arc<UdpSocket>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    while let Some((buffer, src_addr, dst_addr)) = rx.recv().await {
        if buffer[0] == 17 { // UDP
            handle_udp_packet(udp_socket.clone(), &buffer[8..], &src_addr, &dst_addr, state.clone()).await;
        } else if buffer[0] == 6 { // TCP
            if let Some(mut tcp_stream) = tcp_connections.lock().unwrap().get_mut(&dst_addr) {
                handle_tcp_packet(tcp_stream, &buffer[20..], state.clone()).await;
            }
        }
    }
}

async fn cleanup_connections(state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut lock = state.lock().unwrap();
        let to_remove: Vec<_> = lock.iter().filter(|(_, conn_state)| conn_state.last_seen > Duration::from_secs(60)).map(|(&addr, _)| addr).collect();
        for addr in to_remove {
            tcp_connections.lock().unwrap().remove(&addr);
            lock.remove(&addr);
        }
    }
}

async fn main() {
    let (tx, rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>(BUFFER_SIZE * 2);

    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:9999").await.expect("Failed to bind UDP socket"));
    let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:9998").await.expect("Failed to bind TCP listener");
    let state = Arc::new(Mutex::new(HashMap::new()));
    let tcp_connections = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(process_packets(rx, udp_socket.clone(), tcp_connections.clone(), state.clone()));
    tokio::spawn(cleanup_connections(state.clone(), tcp_connections.clone()));

    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let (tx_clone, tcp_listener_clone, udp_socket_clone) = (tx.clone(), tcp_listener.clone(), udp_socket.clone());
        tokio::spawn(async move {
            loop {
                let mut buffer = vec![0; BUFFER_SIZE];
                match tcp_listener_clone.accept().await {
                    Ok((tcp_stream, src_addr)) => {
                        match udp_socket_clone.recv_from(&mut buffer).await {
                            Ok((nread, dst_addr)) => {
                                if nread > 8 {
                                    tx_clone.send((buffer[..nread].to_vec(), src_addr, dst_addr)).await.expect("Failed to send packet");
                                }
                            },
                            Err(_) => {},
                        }
                    },
                    Err(_) => {},
                }
            }
        });
    }

    signal::ctrl_c().await.expect("Failed to listen for ctrl-c");

}
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::select;
use tokio::signal;
use tokio::sync::mpsc;

const BUFFER_SIZE: usize = 1500;
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

struct ConnectionState {
    last_seen: Duration,
    packets_sent: u64,
    packets_received: u64,
}

async fn handle_udp_packet(socket: Arc<UdpSocket>, buffer: &[u8], src_addr: &std::net::SocketAddr, dst_addr: &std::net::SocketAddr, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(src_addr) {
        conn_state.last_seen = tokio::time::Instant::now().duration_since(tokio::time::Instant::now());
        conn_state.packets_received += 1;
    } else {
        lock.insert(*src_addr, ConnectionState { last_seen: tokio::time::Instant::now().duration_since(tokio::time::Instant::now()), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.send_to(buffer, dst_addr).await.expect("Failed to send UDP packet");
}

async fn handle_tcp_packet(socket: Arc<tokio::net::TcpStream>, buffer: &[u8], state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let peer_addr = match socket.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(&peer_addr) {
        conn_state.last_seen = tokio::time::Instant::now().duration_since(tokio::time::Instant::now());
        conn_state.packets_received += 1;
    } else {
        lock.insert(peer_addr, ConnectionState { last_seen: tokio::time::Instant::now().duration_since(tokio::time::Instant::now()), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    socket.write_all(buffer).await.expect("Failed to send TCP packet");
}

async fn process_packets(rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>, udp_socket: Arc<UdpSocket>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>, state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    while let Some((buffer, src_addr, dst_addr)) = rx.recv().await {
        if buffer[0] == 17 { // UDP
            handle_udp_packet(udp_socket.clone(), &buffer[8..], &src_addr, &dst_addr, state.clone()).await;
        } else if buffer[0] == 6 { // TCP
            if let Some(mut tcp_stream) = tcp_connections.lock().unwrap().get_mut(&dst_addr) {
                handle_tcp_packet(tcp_stream, &buffer[20..], state.clone()).await;
            }
        }
    }
}

async fn cleanup_connections(state: Arc<Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>, tcp_connections: Arc<Mutex<HashMap<std::net::SocketAddr, tokio::net::TcpStream>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut lock = state.lock().unwrap();
        let to_remove: Vec<_> = lock.iter().filter(|(_, conn_state)| conn_state.last_seen > Duration::from_secs(60)).map(|(&addr, _)| addr).collect();
        for addr in to_remove {
            tcp_connections.lock().unwrap().remove(&addr);
            lock.remove(&addr);
        }
    }
}

async fn main() {
    let (tx, rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>(BUFFER_SIZE * 2);

    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:9999").await.expect("Failed to bind UDP socket"));
    let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:9998").await.expect("Failed to bind TCP listener");
    let state = Arc::new(Mutex::new(HashMap::new()));
    let tcp_connections = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(process_packets(rx, udp_socket.clone(), tcp_connections.clone(), state.clone()));
    tokio::spawn(cleanup_connections(state.clone(), tcp_connections.clone()));

    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        let (tx_clone, tcp_listener_clone, udp_socket_clone) = (tx.clone(), tcp_listener.clone(), udp_socket.clone());
        tokio::spawn(async move {
            loop {
                let mut buffer = vec![0; BUFFER_SIZE];
                match tcp_listener_clone.accept().await {
                    Ok((tcp_stream, src_addr)) => {
                        match udp_socket_clone.recv_from(&mut buffer).await {
                            Ok((nread, dst_addr)) => {
                                if nread > 8 {
                                    tx_clone.send((buffer[..nread].to_vec(), src_addr, dst_addr)).await.expect("Failed to send packet");
                                }
                            },
                            Err(_) => {},
                        }
                    },
                    Err(_) => {},
                }
            }
        });
    }

    signal::ctrl_c().await.expect("Failed to listen for ctrl-c");

}
