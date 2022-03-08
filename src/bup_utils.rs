#![allow(dead_code)]
use ole_rs::OleFile;

pub async fn check_bup_file(ole_bup_file: &OleFile) {
    let data = ole_bup_file
        .open_stream(&["Details"])
        .expect("unable to get details?");

    let details_string: String = decrypt_bup_string(data);
    println!("details string: {}", details_string);
    let file_data = ole_bup_file
        .open_stream(&["File_0"])
        .expect("unable to get details?");

    let file_data = decrypt_bup_bytes(file_data);
    tokio::fs::write("/tmp/file_0", file_data)
        .await
        .expect("unable to write file?");
}

fn decrypt_bup_string(bup_data: Vec<u8>) -> String {
    bup_data.iter().map(|byte| (byte ^ 0x6A) as char).collect()
}

fn decrypt_bup_bytes(bup_data: Vec<u8>) -> Vec<u8> {
    bup_data.iter().map(|byte| byte ^ 0x6A).collect()
}
