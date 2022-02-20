use std::array::TryFromSliceError;
use std::marker::Unpin;

use chrono::NaiveDateTime;
use derivative::Derivative;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{HeaderErrorType, OleError};

pub mod constants;
pub mod error;

pub trait Readable: Unpin + AsyncRead {}
impl Readable for tokio::fs::File {}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct OleFile {
    header: OleHeader,
    #[derivative(Debug = "ignore")]
    sectors: Vec<Vec<u8>>,
    #[derivative(Debug = "ignore")]
    sector_allocation_table: Vec<u32>,
    #[derivative(Debug = "ignore")]
    short_sector_allocation_table: Vec<u32>,
    #[derivative(Debug = "ignore")]
    directory_stream_data: Vec<u8>,
    directory_entries: Vec<DirectoryEntry>,
    #[derivative(Debug = "ignore")]
    mini_stream: Vec<[u8; 64]>,
}

impl OleFile {
    pub fn list_streams(&self) -> Vec<String> {
        self.directory_entries
            .iter()
            .filter_map(|entry| {
                if entry.object_type == ObjectType::Stream {
                    Some(entry.name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn open_stream(&mut self, stream_name: &str) -> Result<Vec<u8>, OleError> {
        // println!("opening stream: {stream_name}");
        let potential_entries = self
            .directory_entries
            .iter()
            .filter(|entry| entry.name == stream_name);

        for directory_entry in potential_entries {
            if directory_entry.object_type == ObjectType::Stream {
                let mut data = vec![];
                let mut collected_bytes = 0;
                // the unwrap is safe because the location is guaranteed to exist for this object type
                let mut next_sector = directory_entry.starting_sector_location.unwrap();

                if directory_entry.stream_size < self.header.standard_stream_min_size as u64 {
                    // it's in the mini-FAT
                    loop {
                        if next_sector == constants::CHAIN_END {
                            break;
                        } else {
                            let mut sector_data: Vec<u8> = vec![];
                            for byte in self.mini_stream[next_sector as usize] {
                                sector_data.push(byte);
                                collected_bytes += 1;
                                if collected_bytes == directory_entry.stream_size {
                                    break;
                                }
                            }
                            data.extend(sector_data)
                        }
                        next_sector = self.short_sector_allocation_table[next_sector as usize];
                    }
                } else {
                    // it's in the FAT
                    loop {
                        if next_sector == constants::CHAIN_END {
                            break;
                        } else {
                            let mut sector_data: Vec<u8> = vec![];
                            for byte in &self.sectors[next_sector as usize] {
                                sector_data.push(*byte);
                                collected_bytes += 1;
                                if collected_bytes == directory_entry.stream_size {
                                    break;
                                }
                            }
                            data.extend(sector_data)
                        }
                        next_sector = self.sector_allocation_table[next_sector as usize];
                    }
                }
                // println!("data.len(): {}", data.len());
                return Ok(data);
            }
        }
        Err(OleError::DirectoryEntryNotFound)
    }

    pub async fn parse<R>(mut read: R) -> Result<Self, OleError>
    where
        R: Readable,
    {
        // read the header
        let raw_file_header = parse_raw_header(&mut read).await?;
        // println!("raw_file_header: {:#?}", raw_file_header);
        let file_header = OleHeader::from_raw(raw_file_header);
        // println!("file_header: {:#?}", file_header);
        let sector_size = file_header.sector_size as usize;

        //we have to read the remainder of the header if the sector size isn't what we tried to read
        if sector_size > constants::HEADER_LENGTH {
            let should_read_size = sector_size - constants::HEADER_LENGTH;
            let mut should_read = vec![0u8; should_read_size];
            let did_read_size = read.read(&mut should_read).await?;
            if did_read_size != should_read_size {
                return Err(OleError::InvalidHeader(HeaderErrorType::NotEnoughBytes(
                    should_read_size,
                    did_read_size,
                )));
            } else if should_read != vec![0u8; should_read_size] {
                return Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "all bytes must be zero for larger header sizes",
                    "n/a".to_string(),
                )));
            }
        }

        let mut sectors = vec![];
        loop {
            let mut buf = vec![0u8; sector_size];
            match read.read(&mut buf).await {
                Ok(actually_read_size) if actually_read_size == sector_size => {
                    sectors.push((&buf[0..actually_read_size]).to_vec());
                }
                Ok(wrong_size) if wrong_size != 0 => {
                    // TODO: we might have to handle the case where the
                    // TODO: last sector isn't actually complete. Not sure yet.
                    // TODO: the spec says the entire file has to be present here,
                    // TODO: with equal sectors, so I'm doing it this way.
                    return Err(OleError::UnexpectedEof(format!(
                        "short read when parsing sector number: {}",
                        sectors.len()
                    )));
                }
                Ok(_empty) => {
                    break;
                }
                Err(error) => {
                    return Err(OleError::StdIo(error));
                }
            }
        }

        // println!("read_sectors: {}", sectors.len());
        let mut self_to_init = OleFile {
            header: file_header,
            sectors,
            sector_allocation_table: vec![],
            short_sector_allocation_table: vec![],
            directory_stream_data: vec![],
            directory_entries: vec![],
            mini_stream: vec![],
        };

        self_to_init.initialize_sector_allocation_table()?;
        self_to_init.initialize_short_sector_allocation_table()?;
        self_to_init.initialize_directory_stream()?;
        self_to_init.initialize_mini_stream()?;

        Ok(self_to_init)
    }

    fn initialize_sector_allocation_table(&mut self) -> Result<(), OleError> {
        for sector_index in self.header.sector_allocation_table_head.iter() {
            // println!("sector_index: {:#x?}", *sector_index);
            if *sector_index == constants::UNALLOCATED_SECTOR
                || *sector_index == constants::CHAIN_END
            {
                break;
            }
            let sector = self.sectors[*sector_index as usize]
                .chunks_exact(4)
                .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]));
            self.sector_allocation_table.extend(sector);
        }
        // println!(
        //     "sector_allocation_table: {:#x?}",
        //     self.sector_allocation_table
        // );

        if self.header.master_sector_allocation_table_len > 0 {
            return Err(OleError::CurrentlyUnimplemented(
                "MSAT/DI-FAT unsupported todo impl me".to_string(),
            ));
        }

        Ok(())
    }
    fn initialize_short_sector_allocation_table(&mut self) -> Result<(), OleError> {
        if self.header.short_sector_allocation_table_len == 0
            || self.header.short_sector_allocation_table_first_sector == constants::CHAIN_END
        {
            return Ok(()); //no mini stream here
        }

        let mut next_index = self.header.short_sector_allocation_table_first_sector;
        let mut short_sector_allocation_table_raw_data: Vec<u8> = vec![];
        loop {
            // println!("next_index: {:#x?}", next_index);
            if next_index == constants::CHAIN_END {
                break;
            } else {
                short_sector_allocation_table_raw_data
                    .extend(self.sectors[next_index as usize].iter());
            }
            next_index = self.sector_allocation_table[next_index as usize];
        }

        // println!("short_sector_allocation_table_raw_data: {}", short_sector_allocation_table_raw_data.len());

        self.short_sector_allocation_table.extend(
            short_sector_allocation_table_raw_data
                .chunks_exact(4)
                .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])),
        );

        // println!("short_sector_allocation_table: {:#x?}", self.short_sector_allocation_table);

        Ok(())
    }

    fn initialize_directory_stream(&mut self) -> Result<(), OleError> {
        let mut next_directory_index = self.header.sector_allocation_table_first_sector;
        self.directory_stream_data
            .extend(self.sectors[next_directory_index as usize].iter());

        loop {
            next_directory_index =
                self.sector_allocation_table[next_directory_index as usize];
            // println!("next: {:x?}", next);
            if next_directory_index == constants::CHAIN_END {
                break;
            } else {
                self.directory_stream_data
                    .extend(self.sectors[next_directory_index as usize].iter());
            }
        }

        self.initialize_directory_entries()?;

        Ok(())
    }

    fn initialize_directory_entries(&mut self) -> Result<(), OleError> {
        if self.directory_stream_data.len() % constants::SIZE_OF_DIRECTORY_ENTRY != 0 {
            return Err(OleError::InvalidDirectoryEntry(
                "directory_stream_size",
                format!(
                    "size of directory stream data is not correct? {}",
                    self.directory_stream_data.len()
                ),
            ));
        }

        self.directory_entries = Vec::with_capacity(
            self.directory_stream_data.len() / constants::SIZE_OF_DIRECTORY_ENTRY,
        );
        for (index, unparsed_entry) in self
            .directory_stream_data
            .chunks(constants::SIZE_OF_DIRECTORY_ENTRY)
            .enumerate()
        {
            // println!("unparsed_entry: {}", unparsed_entry.len());
            let raw_directory_entry = DirectoryEntryRaw::parse(unparsed_entry)?;
            match DirectoryEntry::from_raw(&self.header, raw_directory_entry, index) {
                Ok(directory_entry) => self.directory_entries.push(directory_entry),
                Err(OleError::UnknownOrUnallocatedDirectoryEntry) => continue,
                Err(anything_else) => return Err(anything_else),
            }
        }

        Ok(())
    }
    fn initialize_mini_stream(&mut self) -> Result<(), OleError> {
        let (mut next_sector, mini_stream_size) = {
            let root_entry = &self.directory_entries[0];
            match root_entry.starting_sector_location {
                None => return Ok(()), //no mini-stream here
                Some(starting_sector_location) => {
                    (starting_sector_location, root_entry.stream_size)
                }
            }
        };

        let mut raw_mini_stream_data: Vec<u8> = vec![];
        loop {
            // println!("next_sector: {:x?}", next_sector);
            if next_sector == constants::CHAIN_END {
                break;
            } else {
                raw_mini_stream_data.extend(self.sectors[next_sector as usize].iter());
            }
            next_sector = self.sector_allocation_table[next_sector as usize];
        }
        raw_mini_stream_data.truncate(mini_stream_size as usize);
        // println!("raw_mini_stream_data {:#?}", raw_mini_stream_data.len());

        //mini streams are sectors of 64 bytes, and the size is guaranteed to be an exact multiple.
        raw_mini_stream_data.chunks_exact(64).for_each(|chunk| {
            //the unwrap is safe because the chunk is guaranteed to be 64 bytes.
            self.mini_stream.push(<[u8; 64]>::try_from(chunk).unwrap());
        });

        // println!("self.mini_stream.len(): {}", self.mini_stream.len());

        Ok(())
    }
}
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct OleHeader {
    major_version: u16,
    minor_version: u16,
    sector_size: u16,
    mini_sector_size: u16,
    directory_sectors_len: u32,
    standard_stream_min_size: u32,
    // sector allocation table AKA "FAT"
    sector_allocation_table_first_sector: u32,
    sector_allocation_table_len: u32,
    // short sector allocation table AKA "mini-FAT"
    short_sector_allocation_table_first_sector: u32,
    short_sector_allocation_table_len: u32,
    // master sector allocation table AKA "DI-FAT"
    master_sector_allocation_table_first_sector: u32,
    master_sector_allocation_table_len: u32,
    // the first 109 FAT sector locations
    #[derivative(Debug = "ignore")]
    sector_allocation_table_head: Vec<u32>,
}

impl OleHeader {
    pub(crate) fn from_raw(raw_file_header: RawFileHeader) -> Self {
        let major_version = u16::from_le_bytes(raw_file_header.major_version);
        let minor_version = u16::from_le_bytes(raw_file_header.minor_version);
        let sector_size = 2u16.pow(u16::from_le_bytes(raw_file_header.sector_size) as u32);
        let mini_sector_size =
            2u16.pow(u16::from_le_bytes(raw_file_header.mini_sector_size) as u32);
        let directory_sectors_len = u32::from_le_bytes(raw_file_header.directory_sectors_len);
        let standard_stream_min_size = u32::from_le_bytes(raw_file_header.standard_stream_min_size);
        let sector_allocation_table_first_sector =
            u32::from_le_bytes(raw_file_header.sector_allocation_table_first_sector);
        let sector_allocation_table_len =
            u32::from_le_bytes(raw_file_header.sector_allocation_table_len);
        let short_sector_allocation_table_first_sector =
            u32::from_le_bytes(raw_file_header.short_sector_allocation_table_first_sector);
        let short_sector_allocation_table_len =
            u32::from_le_bytes(raw_file_header.short_sector_allocation_table_len);
        let master_sector_allocation_table_first_sector =
            u32::from_le_bytes(raw_file_header.master_sector_allocation_table_first_sector);
        let master_sector_allocation_table_len =
            u32::from_le_bytes(raw_file_header.master_sector_allocation_table_len);
        let sector_allocation_table_head = raw_file_header.sector_allocation_table_head;

        OleHeader {
            major_version,
            minor_version,
            sector_size,
            mini_sector_size,
            directory_sectors_len,
            standard_stream_min_size,
            sector_allocation_table_first_sector,
            sector_allocation_table_len,
            short_sector_allocation_table_first_sector,
            short_sector_allocation_table_len,
            master_sector_allocation_table_first_sector,
            master_sector_allocation_table_len,
            sector_allocation_table_head,
        }
    }
}

/**
 * https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc
 * https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
 */
#[derive(Clone, Derivative)]
#[derivative(Debug)]
struct RawFileHeader {
    /**
    Revision number of the file format
    (minor version)
     */
    minor_version: [u8; 2],
    /**
    Version number of the file format
    (major version)
     */
    major_version: [u8; 2],
    /**
    Size of a sector in the compound document file in power-of-two
     */
    sector_size: [u8; 2],
    /**
    Size of a short-sector (mini-sector) in the short-stream container stream in power-of-two
     */
    mini_sector_size: [u8; 2],
    /**
    This integer field contains the count of the number of
    directory sectors in the compound file.
     */
    directory_sectors_len: [u8; 4],
    /**
    Total number of sectors used for the sector allocation table (SAT).
    The SAT is also referred to as the FAT (chain).
     */
    sector_allocation_table_len: [u8; 4],
    /**
    Sector identifier (SID) of first sector of the directory stream (chain).
     */
    sector_allocation_table_first_sector: [u8; 4],
    /**
    Minimum size of a standard stream (in bytes, most used size is 4096 bytes),
    streams smaller than this value are stored as short-streams
     */
    standard_stream_min_size: [u8; 4],
    /**
    Sector identifier (SID) of first sector of the short-sector allocation table (SSAT).
    The SSAT is also referred to as Mini-FAT.
     */
    short_sector_allocation_table_first_sector: [u8; 4],
    /**
    Total number of sectors used for the short-sector allocation table (SSAT).
     */
    short_sector_allocation_table_len: [u8; 4],
    /**
    Sector identifier (SID) of first sector of the master sector allocation table (MSAT).
    The MSAT is also referred to as Double Indirect FAT (DIF).
     */
    master_sector_allocation_table_first_sector: [u8; 4],
    /**
    Total number of sectors used for the master sector allocation table (MSAT).
     */
    master_sector_allocation_table_len: [u8; 4],
    /**
    This array of 32-bit integer fields contains the first 109 FAT sector locations of
    the compound file.
     */
    #[derivative(Debug = "ignore")]
    sector_allocation_table_head: Vec<u32>,
}
async fn parse_raw_header<R>(read: &mut R) -> Result<RawFileHeader, OleError>
where
    R: Readable,
{
    let mut header = [0u8; constants::HEADER_LENGTH];
    let bytes_read = read.read(&mut header).await?;
    if bytes_read != constants::HEADER_LENGTH {
        return Err(OleError::InvalidHeader(HeaderErrorType::NotEnoughBytes(
            constants::HEADER_LENGTH,
            bytes_read,
        )));
    }

    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //Identification signature for the compound file structure, and MUST be
    // set to the value 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1.
    let _: [u8; 8] = (&header[0..8])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing("signature", err.to_string()))
        })
        .and_then(|signature: [u8; 8]| {
            if signature != constants::MAGIC_BYTES {
                Err(OleError::InvalidHeader(HeaderErrorType::WrongMagicBytes(
                    signature.into(),
                )))
            } else {
                Ok(signature)
            }
        })?;

    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //Reserved and unused class ID that MUST be set to all zeroes
    let _: [u8; 16] = (&header[8..24])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "class_identifier",
                err.to_string(),
            ))
        })
        .and_then(|class_identifier| {
            if class_identifier != [0u8; 16] {
                Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "class_identifier",
                    "non-zero entries in class_identifier field".to_string(),
                )))
            } else {
                Ok(class_identifier)
            }
        })?;
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //says this SHOULD be set to 0x003E.
    let minor_version: [u8; 2] = (&header[24..26])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing("minor_version", err.to_string()))
        })
        .and_then(|minor_version| {
            if minor_version != constants::CORRECT_MINOR_VERSION {
                Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "minor_version",
                    format!("incorrect minor version {:x?}", minor_version),
                )))
            } else {
                Ok(minor_version)
            }
        })?;
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //This field MUST be set to either
    // 0x0003 (version 3) or 0x0004 (version 4).
    let major_version: [u8; 2] = (&header[26..28])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing("major_version", err.to_string()))
        })
        .and_then(|major_version: [u8; 2]| match major_version {
            constants::MAJOR_VERSION_3 | constants::MAJOR_VERSION_4 => Ok(major_version),
            _ => Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                "major_version",
                format!("incorrect major version {:x?}", major_version),
            ))),
        })?;
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //This field MUST be set to 0xFFFE. This field is a byte order mark for all integer
    // fields, specifying little-endian byte order.
    let _: [u8; 2] = (&header[28..30])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "byte_order_identifier",
                err.to_string(),
            ))
        })
        .and_then(
            |byte_order_identifier: [u8; 2]| match byte_order_identifier {
                [0xFE, 0xFF] => Ok(byte_order_identifier),
                _ => Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "byte_order_identifier",
                    format!(
                        "incorrect byte order identifier {:x?}",
                        byte_order_identifier
                    ),
                ))),
            },
        )?;
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //This field MUST be set to 0x0009, or 0x000c, depending on the Major
    // Version field. This field specifies the sector size of the compound file as a power of 2.
    //  If Major Version is 3, the Sector Shift MUST be 0x0009, specifying a sector size of 512 bytes.
    //  If Major Version is 4, the Sector Shift MUST be 0x000C, specifying a sector size of 4096 bytes.
    let sector_size: [u8; 2] = (&header[30..32])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing("sector_size", err.to_string()))
        })
        .and_then(|sector_size: [u8; 2]| match major_version {
            constants::MAJOR_VERSION_3 if sector_size == constants::SECTOR_SIZE_VERSION_3 => {
                Ok(sector_size)
            }
            constants::MAJOR_VERSION_4 if sector_size == constants::SECTOR_SIZE_VERSION_4 => {
                Ok(sector_size)
            }
            _ => Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                "sector_size",
                format!(
                    "incorrect sector size {:x?} for major version {:x?}",
                    sector_size, major_version
                ),
            ))),
        })?;
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //This field MUST be set to 0x0006. This field specifies the sector size of
    // the Mini Stream as a power of 2. The sector size of the Mini Stream MUST be 64 bytes.
    let mini_sector_size: [u8; 2] = (&header[32..34])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "mini_sector_size",
                err.to_string(),
            ))
        })
        .and_then(|mini_sector_size: [u8; 2]| match mini_sector_size {
            [0x06, 0x00] => Ok(mini_sector_size),
            _ => Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                "mini_sector_size",
                format!("incorrect mini sector size {:x?}", mini_sector_size),
            ))),
        })?;
    let _: [u8; 6] = (&header[34..40])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing("first_reserved", err.to_string()))
        })
        .and_then(|reserved| {
            if reserved != [0u8; 6] {
                Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "first_reserved",
                    "non-zero entries in reserved field".to_string(),
                )))
            } else {
                Ok(reserved)
            }
        })?;
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
    //If Major Version is 3, the Number of Directory Sectors MUST be zero. This field is not
    // supported for version 3 compound files.
    let directory_sectors_len: [u8; 4] = (&header[40..44])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "directory_sectors_len",
                err.to_string(),
            ))
        })
        .and_then(|directory_sectors_len| {
            if directory_sectors_len != [0u8; 4] && major_version == constants::MAJOR_VERSION_3 {
                Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "directory_sectors_len",
                    "non-zero number of directory sectors with major version 3".to_string(),
                )))
            } else {
                Ok(directory_sectors_len)
            }
        })?;
    let sector_allocation_table_len: [u8; 4] =
        (&header[44..48])
            .try_into()
            .map_err(|err: TryFromSliceError| {
                OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "sector_allocation_table_len",
                    err.to_string(),
                ))
            })?;
    let sector_allocation_table_first_sector: [u8; 4] =
        (&header[48..52])
            .try_into()
            .map_err(|err: TryFromSliceError| {
                OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "sector_allocation_table_first_sector",
                    err.to_string(),
                ))
            })?;
    let _: [u8; 4] = (&header[52..56])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "transaction_signature_number",
                err.to_string(),
            ))
        })?;
    //This integer field MUST be set to 0x00001000. This field
    // specifies the maximum size of a user-defined data stream that is allocated from the mini FAT
    // and mini stream, and that cutoff is 4,096 bytes. Any user-defined data stream that is greater than
    // or equal to this cutoff size must be allocated as normal sectors from the FAT.
    let standard_stream_min_size: [u8; 4] = (&header[56..60])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "standard_stream_min_size",
                err.to_string(),
            ))
        })
        .and_then(|standard_stream_min_size| {
            if standard_stream_min_size != constants::CORRECT_STANDARD_STREAM_MIN_SIZE {
                Err(OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "standard_stream_min_size",
                    format!(
                        "incorrect standard_stream_min_size {:x?}",
                        standard_stream_min_size
                    ),
                )))
            } else {
                Ok(standard_stream_min_size)
            }
        })?;
    let short_sector_allocation_table_first_sector: [u8; 4] = (&header[60..64])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "short_sector_allocation_table_first_sector",
                err.to_string(),
            ))
        })?;
    let short_sector_allocation_table_len: [u8; 4] =
        (&header[64..68])
            .try_into()
            .map_err(|err: TryFromSliceError| {
                OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "short_sector_allocation_table_len",
                    err.to_string(),
                ))
            })?;
    let master_sector_allocation_table_first_sector: [u8; 4] = (&header[68..72])
        .try_into()
        .map_err(|err: TryFromSliceError| {
            OleError::InvalidHeader(HeaderErrorType::Parsing(
                "master_sector_allocation_table_first_sector",
                err.to_string(),
            ))
        })?;
    let master_sector_allocation_table_len: [u8; 4] =
        (&header[72..76])
            .try_into()
            .map_err(|err: TryFromSliceError| {
                OleError::InvalidHeader(HeaderErrorType::Parsing(
                    "master_sector_allocation_table_len",
                    err.to_string(),
                ))
            })?;

    let sector_allocation_table_head = (&header[76..512])
        .chunks_exact(4)
        .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
        .collect::<Vec<_>>();

    Ok(RawFileHeader {
        minor_version,
        major_version,
        sector_size,
        mini_sector_size,
        directory_sectors_len,
        sector_allocation_table_len,
        sector_allocation_table_first_sector,
        standard_stream_min_size,
        short_sector_allocation_table_first_sector,
        short_sector_allocation_table_len,
        master_sector_allocation_table_first_sector,
        master_sector_allocation_table_len,
        sector_allocation_table_head,
    })
}

/**
https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/%5bMS-CFB%5d.pdf
The directory entry array is an array of directory entries that are grouped into a directory sector.
Each storage object or stream object within a compound file is represented by a single directory
entry. The space for the directory sectors that are holding the array is allocated from the FAT.
The valid values for a stream ID, which are used in the Child ID, Right Sibling ID, and Left Sibling
ID fields, are 0 through MAXREGSID (0xFFFFFFFA). The special value NOSTREAM (0xFFFFFFFF) is
used as a terminator.
 */
#[derive(Clone, Derivative)]
#[derivative(Debug)]
struct DirectoryEntryRaw {
    /**
    Directory Entry Name (64 bytes): This field MUST contain a Unicode string for the storage or
    stream name encoded in UTF-16. The name MUST be terminated with a UTF-16 terminating null
    character. Thus, storage and stream names are limited to 32 UTF-16 code points, including the
    terminating null character. When locating an object in the compound file except for the root
    storage, the directory entry name is compared by using a special case-insensitive uppercase
    mapping, described in Red-Black Tree. The following characters are illegal and MUST NOT be part
    of the name: '/', '\', ':', '!'.
     */
    name: [u8; 64],
    /**
    Directory Entry Name Length (2 bytes): This field MUST match the length of the Directory Entry
    Name Unicode string in bytes. The length MUST be a multiple of 2 and include the terminating null
    character in the count. This length MUST NOT exceed 64, the maximum size of the Directory Entry
    Name field.
     */
    name_len: [u8; 2],
    /**
    Object Type (1 byte): This field MUST be 0x00, 0x01, 0x02, or 0x05, depending on the actual type
    of object. All other values are not valid.
    Name Value
    Unknown or unallocated 0x00
    Storage Object 0x01
    Stream Object 0x02
    Root Storage Object 0x05
     */
    object_type: [u8; 1],
    /**
    This field MUST be 0x00 (red) or 0x01 (black). All other values are not valid.
     */
    color_flag: [u8; 1],
    /**
    This field contains the stream ID of the left sibling. If there is no left
    sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF).
    Value Meaning
    REGSID: 0x00000000 — 0xFFFFFFF9
    Regular stream ID to identify the directory entry.
    MAXREGSID: 0xFFFFFFFA
    Maximum regular stream ID.
    NOSTREAM: 0xFFFFFFFF
    If there is no left sibling.
     */
    left_sibling_id: [u8; 4],
    /**
    This field contains the stream ID of the right sibling. If there is no right
    sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF).
    Value Meaning
    REGSID: 0x00000000 — 0xFFFFFFF9
    Regular stream ID to identify the directory entry.
    MAXREGSID: 0xFFFFFFFA
    Maximum regular stream ID.
    NOSTREAM: 0xFFFFFFFF
    If there is no right sibling.
     */
    right_sibling_id: [u8; 4],
    /**
    This field contains the stream ID of a child object. If there is no child object,
    including all entries for stream objects, the field MUST be set to NOSTREAM (0xFFFFFFFF).
    Value Meaning
    REGSID: 0x00000000 — 0xFFFFFFF9
    Regular stream ID to identify the directory entry.
    MAXREGSID: 0xFFFFFFFA
    Maximum regular stream ID.
    NOSTREAM: 0xFFFFFFFF
    If there is no child object
     */
    child_id: [u8; 4],
    /**
    This field contains an object class GUID, if this entry is for a storage object or
    root storage object. For a stream object, this field MUST be set to all zeroes. A value containing all
    zeroes in a storage or root storage directory entry is valid, and indicates that no object class is
    associated with the storage. If an implementation of the file format enables applications to create
    storage objects without explicitly setting an object class GUID, it MUST write all zeroes by default.
    If this value is not all zeroes, the object class GUID can be used as a parameter to start
    applications.
     */
    class_id: [u8; 16],
    /**
    This field contains the user-defined flags if this entry is for a storage object or
    root storage object. For a stream object, this field SHOULD be set to all zeroes because many
    implementations provide no way for applications to retrieve state bits from a stream object. If an
    implementation of the file format enables applications to create storage objects without explicitly
    setting state bits, it MUST write all zeroes by default.
     */
    state_bits: [u8; 4],
    /**
    This field contains the creation time for a storage object, or all zeroes to
    indicate that the creation time of the storage object was not recorded. The Windows FILETIME
    structure is used to represent this field in UTC. For a stream object, this field MUST be all zeroes.
    For a root storage object, this field MUST be all zeroes, and the creation time is retrieved or set on
    the compound file itself
     */
    creation_time: [u8; 8],
    /**
    This field contains the modification time for a storage object, or all
    zeroes to indicate that the modified time of the storage object was not recorded. The Windows
    FILETIME structure is used to represent this field in UTC. For a stream object, this field MUST be
    all zeroes. For a root storage object, this field MAY<2> be set to all zeroes, and the modified time
    is retrieved or set on the compound file itself
     */
    modification_time: [u8; 8],
    /**
    This field contains the first sector location if this is a stream
    object. For a root storage object, this field MUST contain the first sector of the mini stream, if the
    mini stream exists. For a storage object, this field MUST be set to all zeroes
     */
    starting_sector_location: [u8; 4],
    /**
    This 64-bit integer field contains the size of the user-defined data if this is
    a stream object. For a root storage object, this field contains the size of the mini stream. For a
    storage object, this field MUST be set to all zeroes.
     */
    stream_size: [u8; 8],
}

impl DirectoryEntryRaw {
    pub fn parse(unparsed_entry: &[u8]) -> Result<Self, OleError> {
        let name: [u8; 64] =
            unparsed_entry[0..64]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("name", err.to_string())
                })?;
        let name_len: [u8; 2] =
            unparsed_entry[64..66]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("name_len", err.to_string())
                })?;
        let object_type: [u8; 1] =
            unparsed_entry[66..67]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("object_type", err.to_string())
                })?;
        let color_flag: [u8; 1] =
            unparsed_entry[67..68]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("color_flag", err.to_string())
                })?;
        let left_sibling_id: [u8; 4] =
            unparsed_entry[68..72]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("left_sibling_id", err.to_string())
                })?;
        let right_sibling_id: [u8; 4] =
            unparsed_entry[72..76]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("right_sibling_id", err.to_string())
                })?;
        let child_id: [u8; 4] =
            unparsed_entry[76..80]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("child_id", err.to_string())
                })?;
        let class_id: [u8; 16] =
            unparsed_entry[80..96]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("class_id", err.to_string())
                })?;
        let state_bits: [u8; 4] =
            unparsed_entry[96..100]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("state_bits", err.to_string())
                })?;
        let creation_time: [u8; 8] =
            unparsed_entry[100..108]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("creation_time", err.to_string())
                })?;
        let modification_time: [u8; 8] =
            unparsed_entry[108..116]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("modification_time", err.to_string())
                })?;
        let starting_sector_location: [u8; 4] =
            unparsed_entry[116..120]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("starting_sector_location", err.to_string())
                })?;
        let stream_size: [u8; 8] =
            unparsed_entry[120..128]
                .try_into()
                .map_err(|err: TryFromSliceError| {
                    OleError::InvalidDirectoryEntry("stream_size", err.to_string())
                })?;

        Ok(DirectoryEntryRaw {
            name,
            name_len,
            object_type,
            color_flag,
            left_sibling_id,
            right_sibling_id,
            child_id,
            class_id,
            state_bits,
            creation_time,
            modification_time,
            starting_sector_location,
            stream_size,
        })
    }
}

#[derive(Clone, Derivative, Copy, PartialEq)]
#[derivative(Debug)]
pub enum ObjectType {
    Storage,
    Stream,
    RootStorage,
}

#[derive(Clone, Derivative, Copy)]
#[derivative(Debug)]
pub enum NodeColor {
    RED,
    BLACK,
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct DirectoryEntry {
    index: usize, //the index in the directory array
    object_type: ObjectType,
    name: String,
    color: NodeColor,
    left_sibling_id: Option<u32>,
    right_sibling_id: Option<u32>,
    child_id: Option<u32>,

    //TODO: do we need these?
    #[derivative(Debug = "ignore")]
    _class_id_guid: [u8; 16],
    #[derivative(Debug = "ignore")]
    _state_bits: [u8; 4],

    creation_time: Option<NaiveDateTime>,
    modification_time: Option<NaiveDateTime>,
    starting_sector_location: Option<u32>,
    stream_size: u64,
}

impl DirectoryEntry {
    pub(crate) fn from_raw(
        ole_file_header: &OleHeader,
        raw_directory_entry: DirectoryEntryRaw,
        index: usize,
    ) -> Result<Self, OleError> {
        // first, check to see if the directory entry is even allocated...
        let object_type = match raw_directory_entry.object_type {
            constants::OBJECT_TYPE_UNKNOWN_OR_UNALLOCATED => {
                Err(OleError::UnknownOrUnallocatedDirectoryEntry)
            }
            constants::OBJECT_TYPE_ROOT_STORAGE => Ok(ObjectType::RootStorage),
            constants::OBJECT_TYPE_STORAGE => Ok(ObjectType::Storage),
            constants::OBJECT_TYPE_STREAM => Ok(ObjectType::Stream),
            anything_else => Err(OleError::InvalidDirectoryEntry(
                "object_type",
                format!("invalid value: {:x?}", anything_else),
            )),
        }?;

        let name_len = u16::from_le_bytes(raw_directory_entry.name_len);
        let name_raw = &raw_directory_entry.name[0..(name_len as usize)]
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let mut name = String::from_utf16(&name_raw[..])?;
        //drop the null terminator
        let _ = name.pop();
        let color = match raw_directory_entry.color_flag {
            constants::NODE_COLOR_RED => Ok(NodeColor::RED),
            constants::NODE_COLOR_BLACK => Ok(NodeColor::BLACK),
            anything_else  => Err(OleError::InvalidDirectoryEntry(
                "node_color",
                format!("invalid value: {:x?}", anything_else),
            )),
        }?;

        let left_sibling_id = match raw_directory_entry.left_sibling_id {
            constants::NO_STREAM => Ok(None),
            potential_value => {
                let potential_value = u32::from_le_bytes(potential_value);
                if potential_value > constants::MAX_REG_STREAM_ID_VALUE {
                    Err(OleError::InvalidDirectoryEntry(
                        "left_sibling_id",
                        format!("invalid value: {:x?}", potential_value),
                    ))
                } else {
                    Ok(Some(potential_value))
                }
            }
        }?;
        let right_sibling_id = match raw_directory_entry.right_sibling_id {
            constants::NO_STREAM => Ok(None),
            potential_value => {
                let potential_value = u32::from_le_bytes(potential_value);
                if potential_value > constants::MAX_REG_STREAM_ID_VALUE {
                    Err(OleError::InvalidDirectoryEntry(
                        "right_sibling_id",
                        format!("invalid value: {:x?}", potential_value),
                    ))
                } else {
                    Ok(Some(potential_value))
                }
            }
        }?;
        let child_id = match raw_directory_entry.child_id {
            constants::NO_STREAM => Ok(None),
            potential_value => {
                let potential_value = u32::from_le_bytes(potential_value);
                if potential_value > constants::MAX_REG_STREAM_ID_VALUE {
                    Err(OleError::InvalidDirectoryEntry(
                        "child_id",
                        format!("invalid value: {:x?}", potential_value),
                    ))
                } else {
                    Ok(Some(potential_value))
                }
            }
        }?;
        //TODO: the spec says there are some validations we should carry out on these times, but I'm passing them on unmodified.
        let creation_time = match i64::from_le_bytes(raw_directory_entry.creation_time) {
            0 => None,
            time => epochs::windows_file(time),
        };
        let modification_time = match i64::from_le_bytes(raw_directory_entry.modification_time) {
            0 => None,
            time => epochs::windows_file(time),
        };

        // This field contains the first sector location if this is a stream
        // object. For a root storage object, this field MUST contain the first sector of the mini stream, if the
        // mini stream exists. For a storage object, this field MUST be set to all zeroes.
        let starting_sector_location =
            match (object_type, raw_directory_entry.starting_sector_location) {
                (ObjectType::Storage, location) if location != [0x00; 4] => {
                    Err(OleError::InvalidDirectoryEntry(
                        "starting_sector_location",
                        "starting sector location non-zero for storage object type".to_string(),
                    ))
                }
                (ObjectType::Storage, _zero) => Ok(None),
                //the spec says "if the mini stream exists", so i don't think i can do this.
                // (ObjectType::RootStorage, location) if location == [0x00; 4] => {
                //     Err(OleError::InvalidDirectoryEntry(
                //         "starting_sector_location",
                //         format!("missing starting sector location for root storage object type"),
                //     ))
                // }
                (_, location) => Ok(Some(u32::from_le_bytes(location))),
            }?;

        let stream_size = if ole_file_header.major_version == constants::MAJOR_VERSION_3_VALUE {
            /*
            For a version 3 compound file 512-byte sector size, the value of this field MUST be less than
            or equal to 0x80000000. (Equivalently, this requirement can be stated: the size of a stream or
            of the mini stream in a version 3 compound file MUST be less than or equal to 2 gigabytes
            (GB).) Note that as a consequence of this requirement, the most significant 32 bits of this field
            MUST be zero in a version 3 compound file. However, implementers should be aware that
            some older implementations did not initialize the most significant 32 bits of this field, and
            these bits might therefore be nonzero in files that are otherwise valid version 3 compound
            files. Although this document does not normatively specify parser behavior, it is recommended
            that parsers ignore the most significant 32 bits of this field in version 3 compound files,
            treating it as if its value were zero, unless there is a specific reason to do otherwise (for
            example, a parser whose purpose is to verify the correctness of a compound file).
             */
            let mut stream_size_modified = raw_directory_entry.stream_size;
            stream_size_modified[4] = 0x00;
            stream_size_modified[5] = 0x00;
            stream_size_modified[6] = 0x00;
            stream_size_modified[7] = 0x00;

            stream_size_modified
        } else {
            raw_directory_entry.stream_size
        };
        let stream_size = u64::from_le_bytes(stream_size);
        if stream_size != 0 && object_type == ObjectType::Storage {
            return Err(OleError::InvalidDirectoryEntry(
                "stream_size",
                "storage object type has non-zero stream size".to_string(),
            ));
        } else if object_type == ObjectType::RootStorage && stream_size % 64 != 0 {
            return Err(OleError::InvalidDirectoryEntry(
                "stream_size",
                "root storage object type must have stream size % 64 === 0".to_string(),
            ));
        }

        Ok(Self {
            index,
            object_type,
            name,
            color,
            left_sibling_id,
            right_sibling_id,
            child_id,
            _class_id_guid: raw_directory_entry.class_id,
            _state_bits: raw_directory_entry.state_bits,
            creation_time,
            modification_time,
            starting_sector_location,
            stream_size,
        })
    }
}
