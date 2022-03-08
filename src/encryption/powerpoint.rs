use crate::encryption::{DocumentType, EncryptionHandler};
use crate::OleFile;

pub(crate) struct PowerPointEncryptionHandler<'a> {
    ole_file: &'a OleFile,
    stream_name: String,
}

impl<'a> EncryptionHandler<'a> for PowerPointEncryptionHandler<'a> {
    fn doc_type(&self) -> DocumentType {
        DocumentType::PowerPoint
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
