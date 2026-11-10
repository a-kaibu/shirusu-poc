//! Block Container：ファイル内の物理的な記録単位。形式の正は
//! `docs/trace-format.md` の「Block Container」節。
//!
//! ヘッダーは 32 バイト固定。CRC32C は「crc 欄を 0 にしたヘッダー＋
//! payload」を対象とする。計算には shirusu-transport の検証済み
//! CRC32C 実装を再利用する（二重実装を避ける判断。trace-format.md 参照）。

use crate::error::{Result, TraceError};
use std::io::Read;

pub const BLOCK_MAGIC: [u8; 4] = *b"SBLK";
/// File Header payload 先頭のファイル種別マジック。
pub const FILE_MAGIC: [u8; 10] = *b"SHIRUSU\0TR";
pub const HEADER_LEN: usize = 32;
pub const CONTAINER_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
/// stored_len の上限（512 MiB）。
pub const MAX_STORED_LEN: u32 = 512 * 1024 * 1024;
/// raw_len の上限（256 MiB）。展開後サイズの割り当てを縛る。
pub const MAX_RAW_LEN: u32 = 256 * 1024 * 1024;
/// Event / Blob Chunk の非圧縮サイズの目安（256 KiB）。
pub const DEFAULT_CHUNK_RAW_TARGET: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Header,
    Environment,
    Schema,
    EventChunk,
    BlobChunk,
    SchemaCheckpoint,
    Index,
    Finalization,
    Loss,
    Unknown(u8),
}

impl BlockType {
    pub fn code(self) -> u8 {
        match self {
            Self::Header => 1,
            Self::Environment => 2,
            Self::Schema => 3,
            Self::EventChunk => 4,
            Self::BlobChunk => 5,
            Self::SchemaCheckpoint => 6,
            Self::Index => 7,
            Self::Finalization => 8,
            Self::Loss => 9,
            Self::Unknown(c) => c,
        }
    }
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Header,
            2 => Self::Environment,
            3 => Self::Schema,
            4 => Self::EventChunk,
            5 => Self::BlobChunk,
            6 => Self::SchemaCheckpoint,
            7 => Self::Index,
            8 => Self::Finalization,
            9 => Self::Loss,
            c => Self::Unknown(c),
        }
    }
    pub fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd,
}

impl Compression {
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Zstd => 1,
        }
    }
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// Block ヘッダー（CRC を除く論理内容）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub block_type: BlockType,
    pub compression: Compression,
    pub sequence: u64,
    pub stored_len: u32,
    pub raw_len: u32,
}

fn header_crc(header_bytes_with_zero_crc: &[u8], payload: &[u8]) -> u32 {
    let c = shirusu_transport::crc32c::crc32c(header_bytes_with_zero_crc);
    shirusu_transport::crc32c::crc32c_update(c, payload)
}

/// ヘッダーを書き出す（CRC を計算して埋める）。
pub fn serialize_header(header: &BlockHeader, payload: &[u8]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..4].copy_from_slice(&BLOCK_MAGIC);
    out[4] = header.block_type.code();
    out[5] = header.compression.code();
    out[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    out[8..16].copy_from_slice(&header.sequence.to_le_bytes());
    out[16..20].copy_from_slice(&header.stored_len.to_le_bytes());
    out[20..24].copy_from_slice(&header.raw_len.to_le_bytes());
    // out[24..28] は CRC 欄（0 のまま CRC を計算する）
    let crc = header_crc(&out, payload);
    out[24..28].copy_from_slice(&crc.to_le_bytes());
    out
}

/// ヘッダーを検証付きで読む。戻り値は (ヘッダー, CRC が一致したか)。
/// Magic が違う、header_len が 32 でない、reserved が 0 でない場合は
/// None（Block として成立しない）。
pub fn parse_header(bytes: &[u8], payload: &[u8]) -> Option<(BlockHeader, bool)> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let b = &bytes[..HEADER_LEN];
    if b[0..4] != BLOCK_MAGIC {
        return None;
    }
    let header_len = u16::from_le_bytes(b[6..8].try_into().ok()?) as usize;
    if header_len != HEADER_LEN {
        return None;
    }
    let reserved = u32::from_le_bytes(b[28..32].try_into().ok()?);
    if reserved != 0 {
        return None;
    }
    let compression = Compression::from_code(b[5])?;
    let header = BlockHeader {
        block_type: BlockType::from_code(b[4]),
        compression,
        sequence: u64::from_le_bytes(b[8..16].try_into().ok()?),
        stored_len: u32::from_le_bytes(b[16..20].try_into().ok()?),
        raw_len: u32::from_le_bytes(b[20..24].try_into().ok()?),
    };
    let stored_crc = u32::from_le_bytes(b[24..28].try_into().ok()?);
    let mut zeroed = [0u8; HEADER_LEN];
    zeroed.copy_from_slice(b);
    zeroed[24..28].copy_from_slice(&[0; 4]);
    let computed = header_crc(&zeroed, payload);
    Some((header, computed == stored_crc))
}

/// Reader の走査専用：検証前の Block ヘッダー生フィールド。
/// 検証（CRC・長さ上限・圧縮方式）は呼び出し側が回復意味論に従って
/// 段階的に行うため、ここでは値の解釈をしない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawBlockHeader {
    pub block_type_code: u8,
    pub compression_code: u8,
    pub header_len: u16,
    pub sequence: u64,
    pub stored_len: u32,
    pub raw_len: u32,
    pub stored_crc: u32,
    pub reserved: u32,
}

/// 先頭 32 バイトを生フィールドとして読む。Magic が違う、または
/// 32 バイトに満たない場合は None（Block の開始ではない）。
pub fn parse_raw_header(bytes: &[u8]) -> Option<RawBlockHeader> {
    if bytes.len() < HEADER_LEN || bytes[0..4] != BLOCK_MAGIC {
        return None;
    }
    let b = &bytes[..HEADER_LEN];
    Some(RawBlockHeader {
        block_type_code: b[4],
        compression_code: b[5],
        header_len: u16::from_le_bytes(b[6..8].try_into().ok()?),
        sequence: u64::from_le_bytes(b[8..16].try_into().ok()?),
        stored_len: u32::from_le_bytes(b[16..20].try_into().ok()?),
        raw_len: u32::from_le_bytes(b[20..24].try_into().ok()?),
        stored_crc: u32::from_le_bytes(b[24..28].try_into().ok()?),
        reserved: u32::from_le_bytes(b[28..32].try_into().ok()?),
    })
}

/// 生ヘッダーと payload に対する CRC の一致を確かめる。
pub fn raw_header_crc_matches(raw: &RawBlockHeader, header_bytes: &[u8], payload: &[u8]) -> bool {
    if header_bytes.len() < HEADER_LEN {
        return false;
    }
    let mut zeroed = [0u8; HEADER_LEN];
    zeroed.copy_from_slice(&header_bytes[..HEADER_LEN]);
    zeroed[24..28].copy_from_slice(&[0; 4]);
    header_crc(&zeroed, payload) == raw.stored_crc
}

/// チャンクを Zstd フレームへ圧縮する。ruzstd の符号化は `Fastest`
/// （実 LZ 圧縮）と `Uncompressed`（Raw ブロック）のみが実装されて
/// おり、`Default` 等は unimplemented になるため使わない。
pub fn compress_chunk(raw: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(raw, ruzstd::encoding::CompressionLevel::Fastest)
}

/// Zstd フレームを展開する。展開後サイズは `expected_raw_len` と
/// 一致しなければならず、読み取り自体も expected+1 で打ち切る
/// （宣言と異なる巨大な展開結果でメモリを食わせない）。
pub fn decompress_chunk(stored: &[u8], expected_raw_len: u32) -> Result<Vec<u8>> {
    let decoder = ruzstd::decoding::StreamingDecoder::new(stored)
        .map_err(|e| TraceError::ZstdDecode(format!("{e:?}")))?;
    let mut limited = decoder.take(expected_raw_len as u64 + 1);
    let mut out = Vec::with_capacity(expected_raw_len as usize);
    std::io::Read::read_to_end(&mut limited, &mut out)
        .map_err(|e| TraceError::ZstdDecode(e.to_string()))?;
    if out.len() as u64 != expected_raw_len as u64 {
        return Err(TraceError::ZstdDecode(format!(
            "decoded length {} != declared raw_len {}",
            out.len(),
            expected_raw_len
        )));
    }
    Ok(out)
}

/// 圧縮方式に従って Block payload の実バイト列を取り出す。
pub fn decode_payload(header: &BlockHeader, stored: &[u8]) -> Result<Vec<u8>> {
    if header.raw_len > MAX_RAW_LEN {
        return Err(TraceError::CorruptBlock {
            offset: 0,
            reason: format!("raw_len {} exceeds limit", header.raw_len),
        });
    }
    match header.compression {
        Compression::None => {
            if header.stored_len != header.raw_len {
                return Err(TraceError::CorruptBlock {
                    offset: 0,
                    reason: "uncompressed block has stored_len != raw_len".into(),
                });
            }
            Ok(stored.to_vec())
        }
        Compression::Zstd => decompress_chunk(stored, header.raw_len),
    }
}

/// File Header Block の payload（24 バイト固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub container_version: u16,
    pub schema_version: u16,
    pub session_id: u64,
}

impl FileHeader {
    pub fn new(session_id: u64) -> Self {
        Self {
            container_version: CONTAINER_VERSION,
            schema_version: SCHEMA_VERSION,
            session_id,
        }
    }
    pub fn encode(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..10].copy_from_slice(&FILE_MAGIC);
        out[10..12].copy_from_slice(&self.container_version.to_le_bytes());
        out[12..14].copy_from_slice(&self.schema_version.to_le_bytes());
        // out[14..16] header_flags = 0
        out[16..24].copy_from_slice(&self.session_id.to_le_bytes());
        out
    }
    /// File Header payload を検証付きで読む。長さ 24・Magic・
    /// header_flags（予約、0）のいずれかが違う場合は None。
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 24 || bytes[0..10] != FILE_MAGIC {
            return None;
        }
        // header_flags（予約）は 0 でなければならない（F24）。
        if u16::from_le_bytes(bytes[14..16].try_into().ok()?) != 0 {
            return None;
        }
        Some(Self {
            container_version: u16::from_le_bytes(bytes[10..12].try_into().ok()?),
            schema_version: u16::from_le_bytes(bytes[12..14].try_into().ok()?),
            session_id: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
        })
    }
}
