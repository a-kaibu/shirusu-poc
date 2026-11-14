//! 静的依存情報（L13、overview「観測レベル L0〜L4」節）。
//!
//! インポートテーブル等から分かる静的な依存は、観測レベル（L0〜L4）
//! とは別の情報として記録する。`GetProcAddress` で取得した関数のように
//! 静的依存が無くても呼ばれる API があるためで、静的依存の有無と動的
//! 解決の捕捉は別の話である（動的解決の捕捉自体は L01）。
//!
//! 記録する単位は「対象 exe のインポートテーブルに現れた (DLL,
//! 関数)」で、DLL ごとにまとめて `CaptureEnvironment` の field 10
//! （`static_dependencies`）に載せる。空のときは field 10 を書かない
//! ので旧ファイルと同じバイト列になる（L07 の `modules` と同じ方針）。
//!
//! 対象範囲と境界：
//! - 通常のインポートディレクトリ（data directory 1）のみ。遅延ロード
//!   インポート（delay-load、directory 13）は含まない。遅延ロードは
//!   実行時に初めて解決されるため「静的」ではあるが別経路であり、
//!   含める場合はディスクリプタ形式が異なるため別途の解析が要る。
//! - IAT スロットの RVA は記録しない。IAT 配置はイメージ固有の詳細で
//!   あり、依存そのもの（どの DLL のどの関数か）ではない。フック計画
//!   には `shirusu_hook::pe::ImportSite` が既に持っている。
//! - 収集するのは `capture` の起動対象 exe の直接のインポートのみ。
//!   `attach` では対象 exe のパスを解決しないため空のまま（L23 の
//!   モジュール列挙が対象 exe の特定まで含むようになれば、attach でも
//!   載せられる）。子プロセスの Trace も同じ理由で空のまま。
//! - インポートが読めない（PE でない・壊れている・読めない）場合は
//!   空のままにし、capture 自体は失敗させない。静的依存は診断情報で
//!   あり、記録の成否を左右しない。

use crate::error::ProtoError;
use crate::proto::{ProtoReader, ProtoWriter, WIRE_LEN, WIRE_VARINT};

/// インポートされた関数 1 件。名前インポートでは `name`、序数
/// インポートでは `ordinal` を持つ（両方あることはない）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StaticImport {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

impl StaticImport {
    /// 名前インポート。
    pub fn named(name: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            ordinal: None,
        }
    }

    /// 序数インポート。
    pub fn by_ordinal(ordinal: u16) -> Self {
        Self {
            name: None,
            ordinal: Some(ordinal),
        }
    }

    /// 表示用のラベル。名前が無ければ `#<序数>`。
    pub fn label(&self) -> String {
        match (&self.name, self.ordinal) {
            (Some(n), _) => n.clone(),
            (None, Some(o)) => format!("#{o}"),
            (None, None) => "?".to_string(),
        }
    }

    /// field 1: name, 2: ordinal（ある方だけ書く）。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        // Some("") / Some(0) are distinct from None, so present fields are
        // always emitted (proto3 default omission would drop them; found by
        // the proto_messages fuzz target).
        if let Some(n) = &self.name {
            w.bytes_field(1, n.as_bytes());
        }
        if let Some(o) = self.ordinal {
            w.u64_field_present(2, o as u64);
        }
        w.into_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => m.name = Some(r.value_string()?),
                (2, WIRE_VARINT) => m.ordinal = Some(r.value_u16()?),
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

/// 1 DLL への静的依存。`module` はインポートテーブルに書かれたままの
/// DLL 名（大文字小文字は元のまま）。`imports` はテーブルに現れた順。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StaticDependency {
    pub module: String,
    pub imports: Vec<StaticImport>,
}

impl StaticDependency {
    /// `CaptureEnvironment` の field 10 に埋めるメッセージ。
    /// field 1: module, 2: imports（繰り返し）。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.string_field(1, &self.module);
        for imp in &self.imports {
            w.message_field(2, &imp.encode());
        }
        w.into_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => m.module = r.value_string()?,
                (2, WIRE_LEN) => m.imports.push(StaticImport::decode(r.value_bytes()?)?),
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::CaptureEnvironment;

    #[test]
    fn static_import_roundtrip_named_and_ordinal() {
        for imp in [
            StaticImport::named("CreateFileW"),
            StaticImport::by_ordinal(42),
        ] {
            let back = StaticImport::decode(&imp.encode()).unwrap();
            assert_eq!(back, imp);
        }
    }

    #[test]
    fn static_import_label_prefers_name() {
        assert_eq!(StaticImport::named("ReadFile").label(), "ReadFile");
        assert_eq!(StaticImport::by_ordinal(7).label(), "#7");
    }

    #[test]
    fn static_dependency_roundtrip_preserves_order() {
        let dep = StaticDependency {
            module: "kernel32.dll".into(),
            imports: vec![
                StaticImport::named("CreateFileW"),
                StaticImport::by_ordinal(42),
                StaticImport::named("CloseHandle"),
            ],
        };
        let back = StaticDependency::decode(&dep.encode()).unwrap();
        assert_eq!(back, dep);
    }

    #[test]
    fn empty_dependency_roundtrips() {
        let dep = StaticDependency::default();
        let back = StaticDependency::decode(&dep.encode()).unwrap();
        assert_eq!(back, dep);
        assert!(back.imports.is_empty());
    }

    #[test]
    fn environment_roundtrip_keeps_static_dependencies() {
        let mut env = CaptureEnvironment::default();
        env.static_dependencies.push(StaticDependency {
            module: "kernel32.dll".into(),
            imports: vec![StaticImport::named("CreateFileW")],
        });
        env.static_dependencies.push(StaticDependency {
            module: "user32.dll".into(),
            imports: vec![
                StaticImport::named("MessageBoxW"),
                StaticImport::by_ordinal(3),
            ],
        });
        let back = CaptureEnvironment::decode(&env.encode()).unwrap();
        assert_eq!(back.static_dependencies, env.static_dependencies);
    }

    #[test]
    fn environment_without_static_dependencies_writes_no_field_10() {
        // L07 の modules と同じ方針：空のときは field 10 を書かない。
        // 空の Environment の符号化に field 10 が現れないことを、
        // ワイヤを走査して直接確かめる。
        use crate::proto::ProtoReader;
        let env = CaptureEnvironment::default();
        let bytes = env.encode();
        let mut r = ProtoReader::new(&bytes);
        while let Some((f, wire)) = r.next_field().unwrap() {
            assert_ne!(f, 10, "empty static_dependencies must not emit field 10");
            r.skip(wire).unwrap();
        }
        let back = CaptureEnvironment::decode(&bytes).unwrap();
        assert!(back.static_dependencies.is_empty());
    }
}
