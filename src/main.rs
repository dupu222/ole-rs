use ole_rs::OleFile;

#[tokio::main]
async fn main() {
    let file = tokio::fs::File::open("./ole_files/bup_test.bup")
        .await
        .expect("no file?");
    let mut ole_file = OleFile::parse(file).await.expect("error parsing file");

    println!("parsed file: {:#?}", ole_file);
    let data = ole_file
        .open_stream("Details")
        .expect("unable to get details?");

    let details_string: String = decrypt_bup_string(data);
    println!("details string: {}", details_string);
    let file_data = ole_file
        .open_stream("File_0")
        .expect("unable to get details?");

    let file_data = decrypt_bup_bytes(file_data);
    // tokio::fs::write("/tmp/file_0", file_data)
    //     .await
    //     .expect("unable to write file?");

    // let entries = ole_file.list_streams();
    // println!("entries: {entries:?}");
    //
    // let file_2 = tokio::fs::File::open("./ole_files/oledoc1.doc_")
    //     .await
    //     .expect("no file?");
    // let mut ole_file_2 = OleFile::parse(file_2).await.expect("error parsing file");
    //
    // // println!("ole_file_2: {ole_file_2:#?}");
    // let entries_2 = ole_file_2.list_streams();
    // println!("entries_2: {entries_2:#?}");
    //
    // let file_3 = tokio::fs::File::open("./ole_files/maldoc.xls")
    //     .await
    //     .expect("no file?");
    // let mut ole_file_3 = OleFile::parse(file_3).await.expect("error parsing file");
    //
    // println!("ole_file_3: {ole_file_3:#?}");
    // let entries_3 = ole_file_3.list_streams();
    // println!("entries_3: {entries_3:#?}");
}

fn decrypt_bup_string(bup_data: Vec<u8>) -> String {
    bup_data.iter().map(|byte| (byte ^ 0x6A) as char).collect()
}

fn decrypt_bup_bytes(bup_data: Vec<u8>) -> Vec<u8> {
    bup_data.iter().map(|byte| byte ^ 0x6A).collect()
}
