use std::process::Command;

const API_TOKEN: &str = "demo-rust-token-123456789";

fn vulnerable(user_path: &str, user_command: &str) {
    let _contents = std::fs::read_to_string(user_path).unwrap();
    let _result = Command::new("sh").arg("-c").arg(user_command).output();
    let _predictable = rand::random::<u32>();
}
