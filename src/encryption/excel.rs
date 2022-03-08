use crate::encryption::{DocumentType, EncryptionHandler};
use crate::OleFile;

pub(crate) struct ExcelEncryptionHandler<'a> {
    ole_file: &'a OleFile,
    stream_name: String,
}

impl<'a> EncryptionHandler<'a> for ExcelEncryptionHandler<'a> {
    fn doc_type(&self) -> DocumentType {
        DocumentType::Excel
    }

    fn is_encrypted(&self) -> bool {
        false
    }

    fn new(ole_file: &'a OleFile, stream_name: String) -> Self {
        Self {
            ole_file,
            stream_name,
        }
    }
}
