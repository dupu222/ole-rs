use crate::encryption::{DocumentType, EncryptionHandler};
use crate::OleFile;

pub(crate) struct OpenOfficeXmlEncryptionHandler<'a> {
    ole_file: &'a OleFile,
    stream_name: String,
}

impl<'a> EncryptionHandler<'a> for OpenOfficeXmlEncryptionHandler<'a> {
    fn doc_type(&self) -> DocumentType {
        DocumentType::Ooxml
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
