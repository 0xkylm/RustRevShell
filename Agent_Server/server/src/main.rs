use std::env::args;
use std::io::prelude::*;
use std::net::TcpListener;
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.1.86:1337")?;
    let clients = Arc::new(Mutex::new(vec![]));

    loop {
        let (stream, _) = listener.accept()?;
        let clients_ref = clients.clone();

        let _handle = thread::spawn(move || {
            let mut client = stream.try_clone().unwrap();
            let client_addr = client.peer_addr().unwrap();
            println!("Connected to: {}", client_addr);

            {
                let mut clients = clients_ref.lock().unwrap();
                clients.push(client.try_clone().unwrap());
                println!("Clients are {:?}", clients);
            }

            loop {
                let mut buffer = [0; 8192];

                match client.read(&mut buffer) {
                    Ok(0) => {
                        println!("Client {} disconnected", client_addr);
                        let mut clients = clients_ref.lock().unwrap();
                        clients.retain(|c| c.peer_addr().unwrap() != client_addr);
                        break;
                    }
                    Ok(n) => {
                        let decrypted_buffer = uncrypt(buffer[..n].to_vec());
                        let message = String::from_utf8_lossy(&decrypted_buffer[..])
                            .trim()
                            .to_string();
                        println!("Received from {}: {}", client_addr, message);

                        let clients = clients_ref.lock().unwrap();
                        for mut c in clients.iter() {
                            if c.peer_addr().unwrap() != client_addr {
                                let encrypted_message = crypt(decrypted_buffer.clone());
                                c.write(&encrypted_message).unwrap();
                            }
                        }
                    }
                    Err(_) => {
                        println!("Error reading from client {}", client_addr);
                        break;
                    }
                }
            }
        });
    }
}

fn crypt(buffer: Vec<u8>) -> Vec<u8> {
    // buffer.iter().map(|b| b ^ 42).collect()
    buffer
}

fn uncrypt(buffer: Vec<u8>) -> Vec<u8> {
    //buffer.iter().map(|b| b ^ 42).collect()
    buffer
}
