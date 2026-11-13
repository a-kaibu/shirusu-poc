//! Blob：内容の BLAKE3 ハッシュで識別するバイナリ塊と、その永続ストア。
//!
//! Blob ID が同じでも「データが同じ」だけであって、Windows オブジェクト
//! の同一性とは無関係（overview の注意）。ストアは「同じ内容は一度だけ
//! 格納する」重複排除を担う。

use crate::error::{Result, TraceError};
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;

/// Blob の識別子 = 内容の BLAKE3 ハッシュ（32 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    pub fn of_content(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Blob の部分的な更新（F18。overview「チャンク、圧縮、Blob」節）。
///
/// 1 件の更新は「Resource ID、オフセット、サイズ、更新内容」で表す。
/// Resource ID は、そのリソースを最初に確立した基底 Blob の ID
/// （内容の BLAKE3 ハッシュ）である。更新は基底内容の
/// `[offset..offset+size)` を `data` で置き換える。長さは変わらない
/// （範囲外の更新は無効）。`new_version_id` は更新適用後の内容全体の
/// BLAKE3 であり、呼び出し側（更新後の全体内容を観測した記録側）が
/// 求めて渡す。Reader は畳み込み結果のハッシュと照合し、食い違えば
/// その更新を適用しない（Blob ID は内容ハッシュそのもの、という
/// 設計を更新経路でも守る）。
///
/// 符号化（payload。Block レベルの Zstd / 無圧縮は可逆圧縮のみ）:
/// `resource_id` 32 バイト＋`new_version_id` 32 バイト＋`offset`
/// u64 LE＋`size` u32 LE（`data` の長さと等しくなければならない）
/// ＋`data` `size` バイト。`size` が残りバイト数と違う場合は破損。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobUpdate {
    /// 更新対象のリソース（基底 Blob）の ID。
    pub resource_id: BlobId,
    /// 更新適用後の内容全体の BLAKE3。
    pub new_version_id: BlobId,
    /// 置き換え開始位置（基底内容の先頭からのバイトオフセット）。
    pub offset: u64,
    /// 置き換えるバイト列。
    pub data: Vec<u8>,
}

/// `BlobUpdate::encode` の固定ヘッダー長
/// （resource 32 + new version 32 + offset 8 + size 4）。
pub const BLOB_UPDATE_HEADER_LEN: usize = 76;

impl BlobUpdate {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BLOB_UPDATE_HEADER_LEN + self.data.len());
        out.extend_from_slice(self.resource_id.as_bytes());
        out.extend_from_slice(self.new_version_id.as_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }
    /// 復号する。短すぎる、または宣言サイズが残りと食い違う場合は None。
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < BLOB_UPDATE_HEADER_LEN {
            return None;
        }
        let size = u32::from_le_bytes(bytes[72..76].try_into().ok()?) as usize;
        if bytes.len() != BLOB_UPDATE_HEADER_LEN + size {
            return None;
        }
        Some(Self {
            resource_id: BlobId::from_bytes(bytes[0..32].try_into().ok()?),
            new_version_id: BlobId::from_bytes(bytes[32..64].try_into().ok()?),
            offset: u64::from_le_bytes(bytes[64..72].try_into().ok()?),
            data: bytes[BLOB_UPDATE_HEADER_LEN..].to_vec(),
        })
    }
}

/// 基底内容へ部分更新を 1 件適用する。`offset + data.len()` が基底長を
/// 超える（u64 オーバーフローを含む）場合は None。空の更新は無変更
/// （`offset == base.len()` まで許容）。呼び出し側は戻り値のハッシュが
/// 宣言した新版 ID と一致することを別途確かめる（Reader が行う）。
pub fn apply_update_to(base: &[u8], offset: u64, data: &[u8]) -> Option<Vec<u8>> {
    let offset = usize::try_from(offset).ok()?;
    let end = offset.checked_add(data.len())?;
    if end > base.len() {
        return None;
    }
    let mut out = base.to_vec();
    out[offset..end].copy_from_slice(data);
    Some(out)
}

/// ディレクトリ配置の Blob ストア。`<root>/<先頭2hex>/<全体hex>` の2段。
/// 書き込みは「無ければ書く」。同一内容の再 put は格納しない。
pub struct BlobStore {
    root: PathBuf,
    stored: HashSet<BlobId>,
}

impl BlobStore {
    /// ストアを開く（無ければ作る）。既存ファイルは走査して既出集合に
    /// 入れるため、プロセス再起動をまたいでも重複排除が効く。
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        let mut stored = HashSet::new();
        if let Ok(dirs) = std::fs::read_dir(&root) {
            for dir in dirs.flatten() {
                let name = dir.file_name().to_string_lossy().into_owned();
                if name.len() != 2 || !dir.path().is_dir() {
                    continue;
                }
                if let Ok(files) = std::fs::read_dir(dir.path()) {
                    for file in files.flatten() {
                        let fname = file.file_name().to_string_lossy().into_owned();
                        if let Some(id) = BlobId::parse_hex(&fname) {
                            stored.insert(id);
                        }
                    }
                }
            }
        }
        Ok(Self { root, stored })
    }
    fn path_of(&self, id: &BlobId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join(&hex[..2]).join(hex)
    }
    /// 内容を格納し、(Blob ID, 新規に格納したか) を返す。
    /// 既出なら書き込まない（重複排除）。
    pub fn put(&mut self, data: &[u8]) -> Result<(BlobId, bool)> {
        let id = BlobId::of_content(data);
        if self.stored.contains(&id) {
            return Ok((id, false));
        }
        let path = self.path_of(&id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, data)?;
        self.stored.insert(id);
        Ok((id, true))
    }
    pub fn contains(&self, id: &BlobId) -> bool {
        self.stored.contains(id)
    }
    /// 格納済みの異なる Blob の数。
    pub fn stored_count(&self) -> usize {
        self.stored.len()
    }
    /// 内容を読む。無ければ Ok(None)。
    pub fn get(&self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        if !self.stored.contains(id) {
            return Ok(None);
        }
        match std::fs::read(self.path_of(id)) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    /// 内容を読み、BLAKE3 が ID と一致することも確かめる。
    /// 書き込み途中の不完全ファイルや改竄を検出するための経路。
    pub fn get_verified(&self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        match self.get(id)? {
            None => Ok(None),
            Some(data) => {
                if BlobId::of_content(&data) != *id {
                    return Err(TraceError::BlobHashMismatch);
                }
                Ok(Some(data))
            }
        }
    }

    /// 基底 Blob へ部分更新を 1 件適用し、更新後の内容を新版として
    /// 格納する（F18）。基底が無ければ `Ok(None)`（何も書かない）。
    /// 範囲外の更新は `Err(InvalidInput)`。新版の ID は畳み込み内容の
    /// BLAKE3 であり、既出なら格納せず同じ ID を返す（重複排除）。
    /// 戻り値は `Some((新版 ID, 新規に格納したか))`。
    pub fn apply_update(
        &mut self,
        base: &BlobId,
        offset: u64,
        data: &[u8],
    ) -> Result<Option<(BlobId, bool)>> {
        let Some(base_data) = self.get(base)? else {
            return Ok(None);
        };
        let Some(folded) = apply_update_to(&base_data, offset, data) else {
            return Err(TraceError::InvalidInput(format!(
                "blob update out of range: offset {offset} + size {} exceeds base length {}",
                data.len(),
                base_data.len()
            )));
        };
        Ok(Some(self.put(&folded)?))
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// 部分更新は長さを変えず、範囲内だけを置き換える。範囲外・あふれは拒否する。
    #[kani::proof]
    #[kani::unwind(6)]
    fn apply_update_preserves_length_and_outside_bytes() {
        let base: [u8; 4] = kani::any();
        let data: [u8; 2] = kani::any();
        let data_len: usize = kani::any();
        kani::assume(data_len <= data.len());
        let offset: u64 = kani::any();
        let data = &data[..data_len];
        match apply_update_to(&base, offset, data) {
            Some(out) => {
                assert!(out.len() == base.len());
                let o = offset as usize;
                assert!(o + data_len <= base.len());
                let i: usize = kani::any();
                kani::assume(i < base.len());
                if i >= o && i < o + data_len {
                    assert!(out[i] == data[i - o]);
                } else {
                    assert!(out[i] == base[i]);
                }
            }
            None => assert!(offset.saturating_add(data_len as u64) > base.len() as u64),
        }
    }
}
