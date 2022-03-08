mod bup_utils;

use ole_rs::OleFile;

#[tokio::main]
async fn main() {
    let file = tokio::fs::File::open("ole_files/encryption/encrypted/rc4cryptoapi_password.doc")
        .await
        .expect("no file?");

    let ole_file = match OleFile::parse(file).await {
        Ok(ole_file) => ole_file,
        Err(error) => {
            eprintln!(
                "error parsing ole file, invalid or not an OLE file.  error details: {}",
                error
            );
            std::process::exit(1);
        }
    };

    // println!("parsed file: {:#?}", ole_file);
    // bup_utils::check_bup_file(&ole_file).await;

    // let entries = ole_file.list_streams();
    // println!("entries: {entries:?}");
    //
    // let file_2 = tokio::fs::File::open("./ole_files/oledoc1.doc_")
    //     .await
    //     .expect("no file?");
    // let ole_file_2 = OleFile::parse(file_2).await.expect("error parsing file");
    //
    // // println!("ole_file_2: {ole_file_2:#?}");
    // let entries_2 = ole_file_2.list_streams();
    // println!("entries_2: {entries_2:#?}");
    //
    // let file_3 = tokio::fs::File::open("./ole_files/maldoc.xls")
    //     .await
    //     .expect("no file?");
    // let ole_file_3 = OleFile::parse(file_3).await.expect("error parsing file");
    //
    // println!("ole_file_3: {ole_file_3:#?}");
    // let entries_3 = ole_file_3.list_streams();
    // println!("entries_3: {entries_3:#?}");
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    pub async fn test_word_encryption_detection_on() {
        let file = tokio::fs::File::open("ole_files/encryption/encrypted/rc4cryptoapi_password.doc")
            .await
            .expect("no file?");

        let ole_file = OleFile::parse(file).await.unwrap();

        assert!(ole_file.encrypted);
    }

    #[tokio::test]
    pub async fn test_word_encryption_detection_off() {
        let file = tokio::fs::File::open("ole_files/encryption/plaintext/plain.doc")
            .await
            .expect("no file?");

        let ole_file = OleFile::parse(file).await.unwrap();

        assert!(!ole_file.encrypted);
    }
}