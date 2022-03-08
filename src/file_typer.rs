use std::collections::HashMap;

use lazy_static::lazy_static;

use crate::DirectoryEntry;

#[derive(Copy, Clone, Debug)]
pub enum OleFileType {
    Word97,
    Word6,
    Excel97,
    Excel5,
    Powerpoint97,
    Generic,
}

type RootClassId = &'static str;

lazy_static! {
    pub static ref OLE_FILE_TYPE_MAP: HashMap<RootClassId, OleFileType> = {
        HashMap::from([
            ("00020906-0000-0000-C000-000000000046", OleFileType::Word97),
            ("00020900-0000-0000-C000-000000000046", OleFileType::Word6),
            ("00020820-0000-0000-C000-000000000046", OleFileType::Excel97),
            ("00020810-0000-0000-C000-000000000046", OleFileType::Excel5),
            (
                "64818D10-4F9B-11CF-86EA-00AA00B929E8",
                OleFileType::Powerpoint97,
            ),
        ])
    };
}

pub fn type_file(root: &DirectoryEntry) -> OleFileType {
    root.class_id
        .as_ref()
        .map(|class_id| {
            (*OLE_FILE_TYPE_MAP)
                .get(class_id.as_str())
                .cloned()
                .unwrap_or(OleFileType::Generic)
        })
        .unwrap_or(OleFileType::Generic)
}
