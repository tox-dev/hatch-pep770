//! Zip archives read as Python's zipfile reads them, and rewritten without recompressing the members they keep.

use std::borrow::Cow;
use std::fs::File;
use std::path::Path;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::pyrepr::repr;

/// why zipfile refuses an archive or a member
#[derive(Debug)]
pub enum ZipError {
    /// zipfile.BadZipFile
    Bad(String),
    /// zlib.error, raised as late as a member's last read
    Zlib(String),
    /// what zipfile raises outside BadZipFile: encryption, unsupported methods and versions
    Unsupported(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ZipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bad(message) | Self::Zlib(message) | Self::Unsupported(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<std::io::Error> for ZipError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

type ZipResult<T> = std::result::Result<T, ZipError>;

fn bad(message: impl Into<String>) -> ZipError {
    ZipError::Bad(message.into())
}

pub enum Data {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
    Empty,
}

impl std::ops::Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(map) => map,
            Self::Owned(bytes) => bytes,
            Self::Empty => &[],
        }
    }
}

impl Data {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() == 0 {
            return Ok(Self::Empty);
        }
        // SAFETY: the archive is only read; a writer changing it underneath is outside what zipfile guards against too
        Ok(Self::Mapped(unsafe { memmap2::Mmap::map(&file)? }))
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    /// the name zipfile reports, after its sanitizing
    pub name: String,
    orig_name: String,
    pub flags: u16,
    pub method: u16,
    pub crc: u32,
    pub compressed_size: u64,
    pub size: u64,
    /// where the local header starts in the file, prepended data included
    pub header_offset: u64,
    pub create_version: u8,
    pub create_system: u8,
    pub extract_version: u8,
    pub reserved: u8,
    pub internal_attr: u16,
    pub external_attr: u32,
    pub dos_time: u16,
    pub dos_date: u16,
    pub raw_name: Vec<u8>,
    pub extra: Vec<u8>,
    pub comment: Vec<u8>,
    end_offset: u64,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

}

pub struct Archive {
    pub data: Data,
    pub entries: Vec<Entry>,
    /// where the central directory starts in the file
    pub start_dir: u64,
    pub comment: Vec<u8>,
}

const EOCD: &[u8; 4] = b"PK\x05\x06";
const EOCD64: &[u8; 4] = b"PK\x06\x06";
const EOCD64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const LOCAL: &[u8; 4] = b"PK\x03\x04";
const SIZE_EOCD: usize = 22;
const SIZE_CENTRAL: usize = 46;
const SIZE_LOCAL: usize = 30;
const SIZE_EOCD64: usize = 56;
const SIZE_EOCD64_LOCATOR: usize = 20;
const ZIP64_LIMIT: u64 = (1 << 31) - 1;

include!("cp437.rs");

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&data[at..at + 8]);
    u64::from_le_bytes(bytes)
}

fn decode_name(raw: &[u8], utf8: bool) -> ZipResult<String> {
    if utf8 {
        return String::from_utf8(raw.to_vec()).map_err(|error| ZipError::Unsupported(format!("'utf-8' codec can't decode byte: {error}")));
    }
    Ok(raw.iter().map(|&byte| if byte < 0x80 { char::from(byte) } else { CP437_HIGH[usize::from(byte - 0x80)] }).collect())
}

/// `_sanitize_filename`: cut at the first NUL, separators made forward
fn sanitize(name: &str) -> String {
    let name = name.split('\0').next().unwrap_or("");
    if cfg!(windows) { name.replace('\\', "/") } else { name.to_owned() }
}

struct EndRecord {
    entries: u64,
    size_cd: u64,
    offset_cd: u64,
    disk: u32,
    disk_start: u32,
    location: u64,
    comment: Vec<u8>,
}

fn end_record(data: &[u8]) -> ZipResult<Option<EndRecord>> {
    let length = data.len();
    if length < SIZE_EOCD {
        return Ok(None);
    }
    let parse = |start: usize| -> Option<EndRecord> {
        let record = data.get(start..start + SIZE_EOCD)?;
        let comment_size = usize::from(u16_at(record, 20));
        let comment_start = start + SIZE_EOCD;
        let comment = data[comment_start..(comment_start + comment_size).min(length)].to_vec();
        Some(EndRecord {
            disk: u32::from(u16_at(record, 4)),
            disk_start: u32::from(u16_at(record, 6)),
            entries: u64::from(u16_at(record, 10)),
            size_cd: u64::from(u32_at(record, 12)),
            offset_cd: u64::from(u32_at(record, 16)),
            location: start as u64,
            comment,
        })
    };
    let tail = length - SIZE_EOCD;
    let found = if &data[tail..tail + 4] == EOCD && data[length - 2..] == [0, 0] {
        parse(tail)
    } else {
        let window = length.saturating_sub((1 << 16) + SIZE_EOCD);
        match data[window..].windows(4).rposition(|chunk| chunk == EOCD) {
            Some(position) => match parse(window + position) {
                Some(record) => Some(record),
                None => return Ok(None),
            },
            None => None,
        }
    };
    let Some(mut record) = found else { return Ok(None) };
    zip64_end_record(data, &mut record)?;
    Ok(Some(record))
}

fn zip64_end_record(data: &[u8], record: &mut EndRecord) -> ZipResult<()> {
    let Some(locator) = (record.location as usize).checked_sub(SIZE_EOCD64_LOCATOR) else { return Ok(()) };
    let bytes = &data[locator..locator + SIZE_EOCD64_LOCATOR];
    if &bytes[..4] != EOCD64_LOCATOR {
        return Ok(());
    }
    if u32_at(bytes, 4) != 0 || u32_at(bytes, 16) > 1 {
        return Err(bad("zipfiles that span multiple disks are not supported"));
    }
    let relative = u64_at(bytes, 8) as usize;
    let Some(expected) = locator.checked_sub(SIZE_EOCD64) else {
        return Err(bad("Corrupt zip64 end of central directory locator"));
    };
    if relative > expected {
        return Err(bad("Corrupt zip64 end of central directory locator"));
    }
    let mut start = relative;
    if data.get(start..start + 4) != Some(EOCD64) && relative != expected {
        start = expected;
    }
    let Some(record64) = data.get(start..start + SIZE_EOCD64).filter(|bytes| &bytes[..4] == EOCD64) else {
        return Err(bad("Zip64 end of central directory record not found"));
    };
    record.disk = u32_at(record64, 16);
    record.disk_start = u32_at(record64, 20);
    record.entries = u64_at(record64, 32);
    record.size_cd = u64_at(record64, 40);
    record.offset_cd = u64_at(record64, 48);
    Ok(())
}

/// `zipfile.is_zipfile`
pub fn is_zipfile(path: &Path) -> bool {
    let Ok(data) = Data::open(path) else { return false };
    let Ok(Some(record)) = end_record(&data) else { return false };
    if record.entries == 0 && record.size_cd == 0 && record.offset_cd == 0 {
        return true;
    }
    if record.disk != record.disk_start {
        return false;
    }
    let concat = record.location as i64 - record.size_cd as i64 - record.offset_cd as i64;
    let start = record.offset_cd as i64 + concat;
    record.size_cd >= SIZE_CENTRAL as u64
        && usize::try_from(start).ok().and_then(|start| data.get(start..start + 4)) == Some(&CENTRAL[..])
}

impl Archive {
    pub fn open(path: &Path) -> ZipResult<Self> {
        Self::parse(Data::open(path)?)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> ZipResult<Self> {
        Self::parse(Data::Owned(bytes))
    }

    fn parse(data: Data) -> ZipResult<Self> {
        let Some(record) = end_record(&data)? else { return Err(bad("File is not a zip file")) };
        let concat = record.location as i64 - record.size_cd as i64 - record.offset_cd as i64;
        let start_dir = record.offset_cd as i64 + concat;
        if start_dir < 0 {
            return Err(bad("Bad offset for central directory"));
        }
        let start_dir = start_dir as u64;
        let directory = data
            .get(start_dir as usize..(start_dir + record.size_cd) as usize)
            .unwrap_or_else(|| data.get(start_dir as usize..).unwrap_or(&[]));
        let mut entries = Vec::new();
        let mut position = 0usize;
        while (position as u64) < record.size_cd {
            let Some(header) = directory.get(position..position + SIZE_CENTRAL) else {
                return Err(bad("Truncated central directory"));
            };
            if &header[..4] != CENTRAL {
                return Err(bad("Bad magic number for central directory"));
            }
            let name_length = usize::from(u16_at(header, 28));
            let extra_length = usize::from(u16_at(header, 30));
            let comment_length = usize::from(u16_at(header, 32));
            let mut cursor = position + SIZE_CENTRAL;
            let take = |from: usize, length: usize| directory.get(from..from + length).unwrap_or(&directory[from.min(directory.len())..]).to_vec();
            let raw_name = take(cursor, name_length);
            cursor += name_length;
            let extra = take(cursor, extra_length);
            cursor += extra_length;
            let comment = take(cursor, comment_length);
            let flags = u16_at(header, 8);
            let decoded = decode_name(&raw_name, flags & 0x800 != 0)?;
            let extract_version = header[6];
            if extract_version > 63 {
                return Err(ZipError::Unsupported(format!("zip file version {:.1}", f64::from(extract_version) / 10.0)));
            }
            let mut entry = Entry {
                name: sanitize(&decoded),
                orig_name: decoded,
                flags,
                method: u16_at(header, 10),
                crc: u32_at(header, 16),
                compressed_size: u64::from(u32_at(header, 20)),
                size: u64::from(u32_at(header, 24)),
                header_offset: u64::from(u32_at(header, 42)),
                create_version: header[4],
                create_system: header[5],
                extract_version,
                reserved: header[7],
                internal_attr: u16_at(header, 36),
                external_attr: u32_at(header, 38),
                dos_time: u16_at(header, 12),
                dos_date: u16_at(header, 14),
                raw_name,
                extra,
                comment,
                end_offset: 0,
            };
            decode_extra(&mut entry)?;
            entry.header_offset = (entry.header_offset as i64 + concat) as u64;
            entries.push(entry);
            position += SIZE_CENTRAL + name_length + extra_length + comment_length;
        }
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by_key(|&index| entries[index].header_offset);
        let mut end = start_dir;
        for &index in order.iter().rev() {
            entries[index].end_offset = end;
            end = entries[index].header_offset;
        }
        Ok(Self { data, entries, start_dir, comment: record.comment })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.name.as_str())
    }

    /// `getinfo`: the last member of that name, as zipfile's name table keeps it
    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().rev().find(|entry| entry.name == name)
    }

    /// where a member's stored bytes start, after checking its local header as `ZipFile.open` does
    fn data_start(&self, entry: &Entry) -> ZipResult<usize> {
        let offset = entry.header_offset as usize;
        let Some(header) = self.data.get(offset..offset + SIZE_LOCAL) else { return Err(bad("Truncated file header")) };
        if &header[..4] != LOCAL {
            return Err(bad("Bad magic number for file header"));
        }
        let name_length = usize::from(u16_at(header, 26));
        let extra_length = usize::from(u16_at(header, 28));
        let raw_name = self.data.get(offset + SIZE_LOCAL..offset + SIZE_LOCAL + name_length).unwrap_or(&[]);
        if entry.flags & 0x20 != 0 {
            return Err(ZipError::Unsupported("compressed patched data (flag bit 5)".to_owned()));
        }
        if entry.flags & 0x40 != 0 {
            return Err(ZipError::Unsupported("strong encryption (flag bit 6)".to_owned()));
        }
        let local_name = decode_name(raw_name, u16_at(header, 6) & 0x800 != 0)?;
        if local_name != entry.orig_name {
            return Err(bad(format!(
                "File name in directory {} and header {} differ.",
                repr(&entry.orig_name),
                bytes_repr(raw_name)
            )));
        }
        let start = offset + SIZE_LOCAL + name_length + extra_length;
        if entry.end_offset != entry.header_offset && start as u64 + entry.compressed_size > entry.end_offset {
            return Err(bad(format!("Overlapped entries: {} (possible zip bomb)", repr(&entry.orig_name))));
        }
        if entry.flags & 0x1 != 0 {
            return Err(ZipError::Unsupported(format!("File {} is encrypted, password required for extraction", repr(&entry.name))));
        }
        if !matches!(entry.method, 0 | 8) {
            return Err(ZipError::Unsupported(match entry.method {
                12 | 14 | 93 => format!("compression method {} is not supported by python-sbom's core", entry.method),
                _ => "That compression method is not supported".to_owned(),
            }));
        }
        Ok(start)
    }

    fn stored(&self, entry: &Entry, start: usize) -> &[u8] {
        let end = (start as u64 + entry.compressed_size.min(entry.size)) as usize;
        self.data.get(start..end.min(self.data.len())).unwrap_or(&[])
    }

    /// a member's bytes, checked against its CRC; `None` when they run over `limit`
    pub fn read(&self, entry: &Entry, limit: Option<usize>) -> ZipResult<Option<Cow<'_, [u8]>>> {
        let start = self.data_start(entry)?;
        let content: Cow<'_, [u8]> = if entry.method == 0 {
            let slice = self.stored(entry, start);
            if (slice.len() as u64) < entry.size.min(entry.compressed_size) {
                return Err(bad(format!("Truncated member {}", repr(&entry.name))));
            }
            Cow::Borrowed(slice)
        } else {
            let end = ((start as u64 + entry.compressed_size) as usize).min(self.data.len());
            let cap = limit.map_or(entry.size as usize, |limit| (entry.size as usize).min(limit + 1));
            Cow::Owned(inflate(&self.data[start..end], cap)?)
        };
        if limit.is_some_and(|limit| content.len() > limit) {
            return Ok(None);
        }
        if crc32fast::hash(&content) != entry.crc {
            return Err(bad(format!("Bad CRC-32 for file {}", repr(&entry.name))));
        }
        Ok(Some(content))
    }

    /// stream a member through `update`, checking its CRC at the end
    pub fn stream(&self, entry: &Entry, mut update: impl FnMut(&[u8])) -> ZipResult<u64> {
        let start = self.data_start(entry)?;
        let mut crc = crc32fast::Hasher::new();
        let mut total = 0u64;
        if entry.method == 0 {
            let slice = self.stored(entry, start);
            crc.update(slice);
            update(slice);
            total = slice.len() as u64;
        } else {
            let end = ((start as u64 + entry.compressed_size) as usize).min(self.data.len());
            let input = &self.data[start..end];
            let mut decompress = Decompress::new(false);
            let mut buffer = vec![0u8; 256 * 1024];
            loop {
                let consumed = decompress.total_in() as usize;
                let before = decompress.total_out();
                let status = decompress
                    .decompress(&input[consumed..], &mut buffer, FlushDecompress::None)
                    .map_err(|error| zlib_error(&error))?;
                let mut produced = (decompress.total_out() - before) as usize;
                if total + produced as u64 > entry.size {
                    produced = (entry.size - total) as usize;
                }
                crc.update(&buffer[..produced]);
                update(&buffer[..produced]);
                total += produced as u64;
                if status == Status::StreamEnd || total >= entry.size || (produced == 0 && decompress.total_in() as usize >= input.len()) {
                    break;
                }
            }
        }
        if crc.finalize() != entry.crc {
            return Err(bad(format!("Bad CRC-32 for file {}", repr(&entry.name))));
        }
        Ok(total)
    }

    /// the bytes from a member's local header to the next member, which a rewrite copies as they are
    fn span(&self, entry: &Entry) -> &[u8] {
        &self.data[entry.header_offset as usize..entry.end_offset as usize]
    }
}

fn decode_extra(entry: &mut Entry) -> ZipResult<()> {
    let filename_crc = crc32fast::hash(&entry.raw_name);
    let extra = entry.extra.clone();
    let mut rest = extra.as_slice();
    while rest.len() >= 4 {
        let kind = u16_at(rest, 0);
        let length = usize::from(u16_at(rest, 2));
        if length + 4 > rest.len() {
            return Err(bad(format!("Corrupt extra field {kind:04x} (size={length})")));
        }
        let mut field = &rest[4..length + 4];
        if kind == 0x0001 {
            let mut next = |what: &str| -> ZipResult<u64> {
                if field.len() < 8 {
                    return Err(bad(format!("Corrupt zip64 extra field. {what} not found.")));
                }
                let value = u64_at(field, 0);
                field = &field[8..];
                Ok(value)
            };
            if entry.size == 0xFFFF_FFFF {
                entry.size = next("File size")?;
            }
            if entry.compressed_size == 0xFFFF_FFFF {
                entry.compressed_size = next("Compress size")?;
            }
            if entry.header_offset == 0xFFFF_FFFF {
                entry.header_offset = next("Header offset")?;
            }
        } else if kind == 0x7075 {
            if field.len() < 5 {
                return Err(bad("Corrupt unicode path extra field (0x7075)"));
            }
            if field[0] == 1 && u32_at(field, 1) == filename_crc {
                let name = std::str::from_utf8(&field[5..])
                    .map_err(|_| bad("Corrupt unicode path extra field (0x7075): invalid utf-8 bytes"))?;
                if !name.is_empty() {
                    entry.name = sanitize(name);
                }
            }
        }
        rest = &rest[length + 4..];
    }
    Ok(())
}

fn zlib_error(error: &flate2::DecompressError) -> ZipError {
    ZipError::Zlib(format!("Error -3 while decompressing data: {error}"))
}

/// raw deflate data inflated up to `cap` bytes, as zipfile truncates a member to its stated size
fn inflate(input: &[u8], cap: usize) -> ZipResult<Vec<u8>> {
    // a stated size can lie, so memory grows with what actually inflates
    let mut out = Vec::with_capacity(cap.min(1 << 24));
    let mut decompress = Decompress::new(false);
    while out.len() < cap {
        if out.len() == out.capacity() {
            out.reserve((cap - out.len()).min(1 << 24));
        }
        let (consumed, produced) = (decompress.total_in() as usize, out.len());
        let status = decompress
            .decompress_vec(&input[consumed..], &mut out, FlushDecompress::None)
            .map_err(|error| zlib_error(&error))?;
        if status == Status::StreamEnd || (decompress.total_in() as usize == consumed && out.len() == produced) {
            break;
        }
    }
    out.truncate(cap);
    Ok(out)
}

/// raw deflate at zlib's default level, as zipfile compresses
pub fn deflate(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 3 + 64);
    let mut compress = Compress::new(Compression::new(6), false);
    loop {
        let consumed = compress.total_in() as usize;
        if out.len() == out.capacity() {
            out.reserve(input.len() / 4 + 64);
        }
        let status = compress.compress_vec(&input[consumed..], &mut out, FlushCompress::Finish).expect("deflate cannot fail on memory input");
        if status == Status::StreamEnd {
            return out;
        }
    }
}

fn bytes_repr(raw: &[u8]) -> String {
    let mut out = String::from("b'");
    for &byte in raw {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('\'');
    out
}

/// a member added to an archive, with the attributes zipfile writes for it
pub struct NewMember<'a> {
    pub name: &'a str,
    pub content: &'a [u8],
    pub deflate: bool,
    pub dos_time: u16,
    pub dos_date: u16,
    pub create_version: u8,
    pub create_system: u8,
    pub extract_version: u8,
    pub internal_attr: u16,
    pub external_attr: u32,
}

/// `dostime, dosdate` of a Unix time, clamped to 1980 as zip times start there
pub fn dos_time(epoch: i64) -> (u16, u16) {
    let [year, month, day, hour, minute, second] = crate::model::civil(epoch.max(315_532_800));
    let date = ((year - 1980) << 9 | month << 5 | day) as u16;
    let time = (hour << 11 | minute << 5 | second / 2) as u16;
    (time, date)
}

impl NewMember<'_> {
    fn write(&self, out: &mut Vec<u8>) -> Vec<u8> {
        let header_offset = out.len() as u64;
        let stored: Cow<'_, [u8]> = if self.deflate { Cow::Owned(deflate(self.content)) } else { Cow::Borrowed(self.content) };
        let crc = crc32fast::hash(self.content);
        let flags: u16 = if self.name.is_ascii() { 0 } else { 0x800 };
        let method: u16 = if self.deflate { 8 } else { 0 };
        let name = self.name.as_bytes();
        out.extend_from_slice(LOCAL);
        out.extend_from_slice(&u16::from(self.extract_version).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&self.dos_time.to_le_bytes());
        out.extend_from_slice(&self.dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&stored);
        let mut central = Vec::with_capacity(SIZE_CENTRAL + name.len());
        central.extend_from_slice(CENTRAL);
        central.extend_from_slice(&[self.create_version, self.create_system, self.extract_version, 0]);
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&self.dos_time.to_le_bytes());
        central.extend_from_slice(&self.dos_date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
        central.extend_from_slice(&(self.content.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&self.internal_attr.to_le_bytes());
        central.extend_from_slice(&self.external_attr.to_le_bytes());
        central.extend_from_slice(&(header_offset as u32).to_le_bytes());
        central.extend_from_slice(name);
        central
    }
}

/// a kept member's central record, re-pointed at where its bytes now start
fn central_record(entry: &Entry, header_offset: u64) -> ZipResult<Vec<u8>> {
    if header_offset > ZIP64_LIMIT || entry.size > ZIP64_LIMIT || entry.compressed_size > ZIP64_LIMIT {
        return Err(ZipError::Unsupported("rewriting a zip64 archive is not supported by python-sbom's core".to_owned()));
    }
    let extra = strip_zip64(&entry.extra);
    let mut central = Vec::with_capacity(SIZE_CENTRAL + entry.raw_name.len() + extra.len() + entry.comment.len());
    central.extend_from_slice(CENTRAL);
    central.extend_from_slice(&[entry.create_version, entry.create_system, entry.extract_version, entry.reserved]);
    central.extend_from_slice(&entry.flags.to_le_bytes());
    central.extend_from_slice(&entry.method.to_le_bytes());
    central.extend_from_slice(&entry.dos_time.to_le_bytes());
    central.extend_from_slice(&entry.dos_date.to_le_bytes());
    central.extend_from_slice(&entry.crc.to_le_bytes());
    central.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
    central.extend_from_slice(&(entry.size as u32).to_le_bytes());
    central.extend_from_slice(&(entry.raw_name.len() as u16).to_le_bytes());
    central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    central.extend_from_slice(&(entry.comment.len() as u16).to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&entry.internal_attr.to_le_bytes());
    central.extend_from_slice(&entry.external_attr.to_le_bytes());
    central.extend_from_slice(&(header_offset as u32).to_le_bytes());
    central.extend_from_slice(&entry.raw_name);
    central.extend_from_slice(&extra);
    central.extend_from_slice(&entry.comment);
    Ok(central)
}

fn strip_zip64(extra: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(extra.len());
    let mut rest = extra;
    while rest.len() >= 4 {
        let length = usize::from(u16_at(rest, 2)) + 4;
        let Some(field) = rest.get(..length) else { break };
        if u16_at(rest, 0) != 0x0001 {
            out.extend_from_slice(field);
        }
        rest = &rest[length..];
    }
    out
}

fn end_of_directory(out: &mut Vec<u8>, count: usize, directory_start: u64, comment: &[u8]) {
    let size = out.len() as u64 - directory_start;
    out.extend_from_slice(EOCD);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(count as u16).to_le_bytes());
    out.extend_from_slice(&(count as u16).to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&(directory_start as u32).to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
}

impl Archive {
    /// the archive without the members `drop` names, then `added` after the rest: the kept members' bytes are copied
    /// as stored, in their order on disk, and the central directory keeps its order
    pub fn rewrite(&self, drop: &[&str], added: &[NewMember<'_>]) -> ZipResult<Vec<u8>> {
        if self.entries.len() + added.len() > 0xFFFF {
            return Err(ZipError::Unsupported("rewriting a zip64 archive is not supported by python-sbom's core".to_owned()));
        }
        let kept: Vec<&Entry> = self.entries.iter().filter(|entry| !drop.contains(&entry.name.as_str())).collect();
        let mut physical: Vec<&Entry> = kept.clone();
        physical.sort_by_key(|entry| entry.header_offset);
        let first = self.entries.iter().map(|entry| entry.header_offset).min().unwrap_or(self.start_dir).min(self.start_dir);
        let mut out = Vec::with_capacity(self.data.len() + added.iter().map(|member| member.content.len()).sum::<usize>() + 4096);
        // whatever precedes the first member, such as a zipapp's shebang line
        out.extend_from_slice(&self.data[..first as usize]);
        let mut offsets = std::collections::HashMap::with_capacity(kept.len());
        for entry in physical {
            offsets.insert(entry.header_offset, out.len() as u64);
            out.extend_from_slice(self.span(entry));
        }
        let centrals: Vec<Vec<u8>> = added.iter().map(|member| member.write(&mut out)).collect();
        let directory_start = out.len() as u64;
        for entry in &kept {
            let record = central_record(entry, offsets[&entry.header_offset])?;
            out.extend_from_slice(&record);
        }
        for central in &centrals {
            out.extend_from_slice(central);
        }
        end_of_directory(&mut out, kept.len() + added.len(), directory_start, &self.comment);
        Ok(out)
    }

    /// `ZipFile(path, "a").writestr(...)`: the members stay where they are and the new one goes where the central
    /// directory began
    pub fn append(&self, member: &NewMember<'_>) -> ZipResult<Vec<u8>> {
        let mut out = Vec::with_capacity(self.data.len() + member.content.len() + 1024);
        out.extend_from_slice(&self.data[..self.start_dir as usize]);
        let central = member.write(&mut out);
        let directory_start = out.len() as u64;
        for entry in &self.entries {
            out.extend_from_slice(&central_record(entry, entry.header_offset)?);
        }
        out.extend_from_slice(&central);
        end_of_directory(&mut out, self.entries.len() + 1, directory_start, &self.comment);
        Ok(out)
    }
}
