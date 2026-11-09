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
        if s.len() != 64 {
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
}
