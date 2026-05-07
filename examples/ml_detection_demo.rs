use std::collections::{HashMap, VecDeque};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tokio_util::codec::{FramedRead, LinesCodec};
use futures_util::stream::StreamExt;

struct ConnectionState {
    last_seen: std::time::Instant,
    packets_sent: u32,
    packets_received: u32,
}

async fn handle_udp_packet(udp_socket: &tokio::net::UdpSocket, buffer: &[u8], src_addr: &std::net::SocketAddr, dst_addr: &std::net::SocketAddr, state: std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(src_addr) {
        conn_state.last_seen = std::time::Instant::now();
        conn_state.packets_received += 1;
    } else {
        lock.insert(*src_addr, ConnectionState { last_seen: std::time::Instant::now(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    udp_socket.send_to(buffer, dst_addr).await.expect("Failed to send UDP packet");
}

async fn handle_tcp_packet(tcp_stream: &mut TcpStream, buffer: &[u8], state: std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    let peer_addr = match tcp_stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    let mut lock = state.lock().unwrap();
    if let Some(conn_state) = lock.get_mut(&peer_addr) {
        conn_state.last_seen = std::time::Instant::now();
        conn_state.packets_received += 1;
    } else {
        lock.insert(peer_addr, ConnectionState { last_seen: std::time::Instant::now(), packets_sent: 0, packets_received: 1 });
    }
    drop(lock);
    tcp_stream.write_all(buffer).await.expect("Failed to send TCP packet");
}

async fn process_packets(rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>, udp_socket: std::sync::Arc<tokio::net::UdpSocket>, tcp_connections: std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, TcpStream>>>, state: std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>) {
    while let Some((buffer, src_addr, dst_addr)) = rx.recv().await {
        if buffer[0] == 17 { // UDP
            handle_udp_packet(udp_socket.as_ref(), &buffer[8..], &src_addr, &dst_addr, state.clone()).await;
        } else if buffer[0] == 6 { // TCP
            if let Some(mut tcp_stream) = tcp_connections.lock().unwrap().get_mut(&dst_addr) {
                handle_tcp_packet(tcp_stream, &buffer[20..], state.clone()).await;
            }
        }
    }
}

async fn cleanup_connections(state: std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, ConnectionState>>>, tcp_connections: std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, TcpStream>>>) {
    loop {
        sleep(Duration::from_secs(10)).await;
        let mut lock = state.lock().unwrap();
        let to_remove: Vec<_> = lock.iter().filter(|(_, conn_state)| conn_state.last_seen.elapsed() > Duration::from_secs(60)).map(|(&addr, _)| addr).collect();
        for addr in to_remove {
            tcp_connections.lock().unwrap().remove(&addr);
            lock.remove(&addr);
        }
    }
}

async fn simulate_traffic(tx: mpsc::Sender<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>) {
    let mut rng = rand::thread_rng();
    let addr1 = "192.168.1.1:4500".parse().unwrap();
    let addr2 = "192.168.1.2:4500".parse().unwrap();
    loop {
        let packet_type = rng.gen_range(0..=1);
        let buffer_size = if packet_type == 0 { 32 } else { 64 };
        let mut buffer = vec![packet_type; buffer_size];
        match rng.gen_range(0..=1) {
            0 => tx.send((buffer, addr1, addr2)).await.expect("Failed to send packet"),
            _ => tx.send((buffer, addr2, addr1)).await.expect("Failed to send packet"),
        };
        sleep(Duration::from_millis(rng.gen_range(50..=300))).await;
    }
}

async fn ml_inference_loop(rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>) {
    let mut model = Model::new("data/models/traffic_classifier_v2.onnx");
    while let Some((buffer, src_addr, dst_addr)) = rx.recv().await {
        if let Ok(predictions) = model.predict(&buffer) {
            if predictions.contains(&1.0) { // Assuming 1.0 indicates potential malware
                println!("Potential malware detected from {} to {}", src_addr, dst_addr);
            }
        }
    }
}

struct Model {
    session: onnxruntime::InferenceSession,
    input_name: String,
    output_name: String,
}

impl Model {
    fn new(model_path: &str) -> Self {
        let environment = onnxruntime::Environment::new().expect("Failed to create ONNX environment");
        let session_options = onnxruntime::SessionOptions::default();
        let session = environment.new_session_with_options(model_path, &session_options).expect("Failed to load model");

        let input_name = session.input_names()[0].to_string();
        let output_name = session.output_names()[0].to_string();

        Model { session, input_name, output_name }
    }

    fn predict(&self, data: &[u8]) -> Result<Vec<f32>, onnxruntime::InferenceError> {
        let tensor_values = self.prepare_input(data);
        let inputs = vec![tensor_values];

        let outputs = self.session.run(inputs)?;

        let output_tensor = &outputs[0];
        let output_array = output_tensor.to_vec::<f32>();

        Ok(output_array)
    }

    fn prepare_input(&self, data: &[u8]) -> onnxruntime::Tensor<f32> {
        let input_shape = self.session.input(0).expect("Failed to get model input").dimensions();
        let mut input_data: Vec<f32> = vec![0.0; input_shape.iter().product()];
        for (i, &byte) in data.iter().enumerate() {
            if i < input_data.len() {
                input_data[i] = byte as f32;
            } else {
                break;
            }
        }

        onnxruntime::Tensor::<f32>::try_new(input_shape.clone(), input_data).expect("Failed to create tensor")
    }
}

#[tokio::main]
async fn main() {
    let (tx1, rx1) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>(32);
    let (tx2, rx2) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, std::net::SocketAddr)>(32);

    let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:4500").await.expect("Failed to bind UDP socket");
    let udp_socket_clone = udp_socket.clone();

    let state = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
    let tcp_connections = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        simulate_traffic(tx1).await;
    });

    tokio::spawn(async move {
        process_packets(rx2, udp_socket_clone, tcp_connections.clone(), state.clone()).await;
    });

    tokio::spawn(async move {
        cleanup_connections(state.clone(), tcp_connections.clone()).await;
    });

    tokio::spawn(async move {
        ml_inference_loop(rx1).await;
    });

    loop {
        let mut buf = [0; 256];
        match udp_socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                let dst_addr: std::net::SocketAddr = "192.168.1.2:4500".parse().unwrap(); // Hardcoded destination for demo
                tx2.send((buf[0..n].to_vec(), src_addr, dst_addr)).await.expect("Failed to send packet");
            },
            Err(e) => eprintln!("Error receiving UDP data: {}", e),
        }
    }
}
