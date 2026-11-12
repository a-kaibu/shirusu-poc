//! Inline Hook のトランポリン構築（プラットフォーム非依存。L01）。
//!
//! `GetProcAddress` 経由や間接呼び出しは IAT を通らないため、対象関数
//! の先頭命令そのものを Detour へのジャンプで置き換える。置き換えた
//! 先頭命令（盗んだ命令）はトランポリンへ再配置し、Detour は
//! トランポリン経由で元の関数を呼ぶ。
//!
//! 再配置には `iced-x86` の [`BlockEncoder`] を使う。分岐・呼び出しの
//! 相対アドレスと RIP 相対オペランドを新しい位置に合わせて直し、
//! 届かなくなった短い分岐は長い形へ拡大する。`loop` / `jcxz` のような
//! rel8 しか持たない命令も、短い分岐＋rel32 ジャンプへの書き換えで
//! 届く範囲なら再配置できる。再配置できない場合（BlockEncoder が
//! エラーを返す場合）は、その API の Inline Hook は見送る
//! （fail-closed。IAT 経由の記録は残る）。
//!
//! 制限（正直に記録する）：
//! - 盗んだ範囲の外から、その範囲の途中へ飛ぶ分岐（プロローグ内への
//!   後方ジャンプ等）は検出できない。先頭命令の直後にそのような
//!   分岐を持つ関数は稀だが、存在すれば誤動作し得る。パッチ長は
//!   最小（5 バイト、遠方時のみ 14/10 バイト）に留め、範囲を狭くする。
//! - 必要なパッチ長より前に ret / 無条件分岐等が現れたら拒否する。
//!   続く領域は他の関数やデータかもしれず、上書きしてはならない。

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction, InstructionBlock,
};

/// パッチに使う相対ジャンプの長さ（`E9 rel32`）。
pub const PATCH_LEN_REL32: usize = 5;
/// x64 の絶対間接ジャンプの長さ（`FF 25 00000000` + 8 バイトアドレス）。
pub const PATCH_LEN_ABS64: usize = 14;
/// x86 の絶対間接ジャンプの長さ（`FF 25 disp32` + 4 バイトアドレス）。
pub const PATCH_LEN_ABS32: usize = 10;

/// Inline Hook を見送る理由。呼び出し側は Coverage 欠落として記録する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineRefusal {
    /// 関数先頭の読み取り済みバイト数がパッチに足りない。
    TooShort { available: usize, needed: usize },
    /// 先頭命令をデコードできない（無効なバイト列）。
    DecodeFailed,
    /// 再配置できない命令を含む（BlockEncoder の拒否）。
    Unrelocatable(String),
    /// 未対応のビット数。
    InvalidBitness(u32),
}

impl InlineRefusal {
    /// Coverage へ残す短い理由文字列。
    pub fn reason(&self) -> &'static str {
        match self {
            InlineRefusal::TooShort { .. } => "too-short",
            InlineRefusal::DecodeFailed => "decode-failed",
            InlineRefusal::Unrelocatable(_) => "unrelocatable",
            InlineRefusal::InvalidBitness(_) => "invalid-bitness",
        }
    }
}

/// `from`（ジャンプ命令の直後）から `to` へ相対 32bit ジャンプが届くか。
pub fn rel32_fits(from: u64, to: u64) -> bool {
    let disp = to as i128 - from as i128;
    disp >= i32::MIN as i128 && disp <= i32::MAX as i128
}

/// `target` に置くパッチの長さ。Detour が相対 32bit で届けば 5 バイト、
/// 届かなければ絶対間接ジャンプ（x64: 14 バイト / x86: 10 バイト）。
pub fn patch_len_for(target: u64, detour: u64, bitness: u32) -> usize {
    if rel32_fits(target + PATCH_LEN_REL32 as u64, detour) {
        PATCH_LEN_REL32
    } else if bitness == 64 {
        PATCH_LEN_ABS64
    } else {
        PATCH_LEN_ABS32
    }
}

/// 盗んだ先頭命令の計画。`build_trampoline` がこれを再配置する。
#[derive(Debug, Clone, PartialEq)]
pub struct StolenPlan {
    pub target: u64,
    pub detour: u64,
    pub bitness: u32,
    /// 盗んだバイト数（パッチ長以上。命令境界で区切る）。
    pub stolen_len: usize,
    /// `target` に置くパッチの長さ。
    pub patch_len: usize,
    pub instructions: Vec<Instruction>,
}

/// 関数先頭のバイト列から、盗む命令を決める。
///
/// `bytes` は対象関数の先頭から読んだバイト列（パッチ長以上あること）。
/// 命令境界で区切り、パッチ長以上のバイト数になるまで命令を集める。
pub fn plan_stolen(
    bytes: &[u8],
    target: u64,
    detour: u64,
    bitness: u32,
) -> Result<StolenPlan, InlineRefusal> {
    if bitness != 32 && bitness != 64 {
        return Err(InlineRefusal::InvalidBitness(bitness));
    }
    let patch_len = patch_len_for(target, detour, bitness);
    if bytes.len() < patch_len {
        return Err(InlineRefusal::TooShort {
            available: bytes.len(),
            needed: patch_len,
        });
    }
    let mut decoder = Decoder::new(bitness, bytes, DecoderOptions::NONE);
    decoder.set_ip(target);
    let mut instructions = Vec::new();
    while decoder.position() < patch_len {
        if !decoder.can_decode() {
            return Err(InlineRefusal::TooShort {
                available: bytes.len(),
                needed: patch_len,
            });
        }
        let instr = decoder.decode();
        if instr.code() == Code::INVALID {
            return Err(InlineRefusal::DecodeFailed);
        }
        let forward_inside_patch = instr.flow_control()
            == iced_x86::FlowControl::UnconditionalBranch
            && instr.near_branch_target() >= instr.next_ip()
            && instr.near_branch_target() < target + patch_len as u64;
        if decoder.position() < patch_len
            && !forward_inside_patch
            && matches!(
                instr.flow_control(),
                iced_x86::FlowControl::Return
                    | iced_x86::FlowControl::UnconditionalBranch
                    | iced_x86::FlowControl::IndirectBranch
                    | iced_x86::FlowControl::Exception
                    | iced_x86::FlowControl::Interrupt
            )
        {
            // Bytes after a terminal instruction may belong to another export
            // or hold data. Relocating them does not make overwriting them safe.
            return Err(InlineRefusal::TooShort {
                available: decoder.position(),
                needed: patch_len,
            });
        }
        instructions.push(instr);
    }
    Ok(StolenPlan {
        target,
        detour,
        bitness,
        stolen_len: decoder.position(),
        patch_len,
        instructions,
    })
}

/// `from` に置くジャンプ命令のバイト列。相対 32bit が届けば `E9 rel32`、
/// 届かなければ絶対間接ジャンプ（x64: `FF 25 00000000` の直後に
/// 8 バイトアドレス / x86: `FF 25 disp32` の直後に 4 バイトアドレス。
/// disp32 はアドレススロット自身（`from + 6`）を指す）。
pub fn jump_bytes(from: u64, to: u64, bitness: u32) -> Vec<u8> {
    if rel32_fits(from + PATCH_LEN_REL32 as u64, to) {
        let disp = (to as i64 - (from + PATCH_LEN_REL32 as u64) as i64) as i32;
        let mut v = vec![0xE9];
        v.extend_from_slice(&disp.to_le_bytes());
        v
    } else if bitness == 64 {
        let mut v = vec![0xFF, 0x25, 0, 0, 0, 0];
        v.extend_from_slice(&to.to_le_bytes());
        v
    } else {
        let slot = (from + 6) as u32;
        let mut v = vec![0xFF, 0x25];
        v.extend_from_slice(&slot.to_le_bytes());
        v.extend_from_slice(&(to as u32).to_le_bytes());
        v
    }
}

/// `target` に置くパッチのバイト列（[`jump_bytes`] と同じ）。
pub fn build_patch(target: u64, detour: u64, bitness: u32) -> Vec<u8> {
    jump_bytes(target, detour, bitness)
}

/// 盗んだ命令を `trampoline` へ再配置し、末尾に元の関数への
/// 戻りジャンプ（`target + stolen_len` 行き）を付けたバイト列を返す。
///
/// 戻りジャンプも相対 32bit が届けば 5 バイト、届かなければ絶対形。
/// トランポリンは呼び出し側が実行可能メモリへ書き込むこと。
pub fn build_trampoline(plan: &StolenPlan, trampoline: u64) -> Result<Vec<u8>, InlineRefusal> {
    // InstructionBlock の第 2 引数は配置先の RIP（元の RIP ではない）。
    // ここを間違えると再配置が起きず、元の変位のままコピーされる。
    // Include the continuation in the encoded block. BlockEncoder may append
    // literal addresses for far branches; appending executable bytes after that
    // pool makes a relocated CALL return into data.
    let mut instructions = plan.instructions.clone();
    let back_to = plan.target + plan.stolen_len as u64;
    let back = Instruction::with_branch(
        if plan.bitness == 64 {
            Code::Jmp_rel32_64
        } else {
            Code::Jmp_rel32_32
        },
        back_to,
    )
    .map_err(|e| InlineRefusal::Unrelocatable(e.to_string()))?;
    // Do not assign back_to as this instruction's original IP: a stolen CALL
    // to the continuation must still target the original code, not this jump.
    instructions.push(back);
    let block = InstructionBlock::new(&instructions, trampoline);
    let encoded = BlockEncoder::encode(plan.bitness, block, BlockEncoderOptions::NONE)
        .map_err(|e| InlineRefusal::Unrelocatable(e.to_string()))?;
    Ok(encoded.code_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_overwrite_adjacent_code_after_a_short_function() {
        for prefix in [&[0xc3][..], &[0xeb, 0x20], &[0xff, 0x25, 0, 0, 0, 0]] {
            let mut bytes = prefix.to_vec();
            bytes.resize(32, 0x90);
            assert!(matches!(
                plan_stolen(&bytes, 0x1000, 0x1_0000_0000, 64),
                Err(InlineRefusal::TooShort { .. })
            ));
        }
        // A complete five-byte thunk can still be patched with a near jump.
        assert!(plan_stolen(&[0xe9, 0x20, 0, 0, 0], 0x1000, 0x2000, 64).is_ok());
    }
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    #[test]
    fn far_call_returns_to_jump_before_literal_pool() {
        let target = 0x1400_0000;
        let trampoline = 0x1_4000_0000;
        let plan = plan_stolen(&[0xE8, 0x20, 0, 0, 0], target, target + 4096, 64).unwrap();
        let code = build_trampoline(&plan, trampoline).unwrap();
        let mut decoder = Decoder::with_ip(64, &code, trampoline, DecoderOptions::NONE);
        assert_eq!(decoder.decode().flow_control(), FlowControl::IndirectCall);
        let continuation = decoder.decode();
        assert_eq!(continuation.flow_control(), FlowControl::IndirectBranch);
        let slot = (continuation.ip_rel_memory_address() - trampoline) as usize;
        assert_eq!(
            u64::from_le_bytes(code[slot..slot + 8].try_into().unwrap()),
            target + 5
        );
    }

    /// バイト列の先頭 1 命令を `ip` からデコードする（検証用）。
    fn decode_first(bytes: &[u8], ip: u64, bitness: u32) -> Instruction {
        let mut decoder = Decoder::new(bitness, bytes, DecoderOptions::NONE);
        decoder.set_ip(ip);
        decoder.decode()
    }

    /// バイト列を `ip` からデコードし、命令列を返す（検証用）。
    fn decode_all(bytes: &[u8], ip: u64, bitness: u32) -> Vec<Instruction> {
        let mut decoder = Decoder::new(bitness, bytes, DecoderOptions::NONE);
        decoder.set_ip(ip);
        let mut out = Vec::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.code() == Code::INVALID {
                break;
            }
            out.push(instr);
        }
        out
    }

    #[test]
    fn rel32_reach_decides_patch_len() {
        // 近ければ 5 バイト。
        assert_eq!(patch_len_for(0x1000, 0x2000, 64), 5);
        assert_eq!(patch_len_for(0x1000, 0x2000, 32), 5);
        // 2GB を超えれば絶対形（x64: 14 / x86: 10）。
        assert_eq!(patch_len_for(0x1000, 0x1_0000_1000, 64), 14);
        assert_eq!(patch_len_for(0x1000, 0x9000_0000, 32), 10);
        // 境界：rel32 の上限ちょうどは届く（disp = i32::MAX）。
        let target = 0x1000u64;
        let detour = target + 5 + i32::MAX as u64;
        assert_eq!(patch_len_for(target, detour, 64), 5);
        assert_eq!(patch_len_for(target, detour + 1, 64), 14);
    }

    #[test]
    fn jump_bytes_rel32_encoding() {
        // E9 + disp32（基点は命令直後）。
        assert_eq!(
            jump_bytes(0x1000, 0x2000, 64),
            vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]
        );
        // 後方ジャンプも負の disp で表せる。
        assert_eq!(
            jump_bytes(0x2000, 0x1000, 64),
            vec![0xE9, 0xFB, 0xEF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn jump_bytes_absolute_x64() {
        let bytes = jump_bytes(0x1000, 0x1_0000_1000, 64);
        assert_eq!(bytes.len(), 14);
        assert_eq!(&bytes[..6], &[0xFF, 0x25, 0, 0, 0, 0]);
        assert_eq!(&bytes[6..], &0x1_0000_1000u64.to_le_bytes());
        // デコードして間接ジャンプであることを確認する。アドレススロット
        // の 8 バイトは命令ではないため、先頭 1 命令だけ見る。
        let instr = decode_first(&bytes, 0x1000, 64);
        // メモリ間接ジャンプのため IndirectBranch。
        assert_eq!(instr.flow_control(), FlowControl::IndirectBranch);
        assert!(instr.is_ip_rel_memory_operand());
    }

    #[test]
    fn jump_bytes_absolute_x86() {
        let bytes = jump_bytes(0x1000, 0x9000_0000, 32);
        assert_eq!(bytes.len(), 10);
        assert_eq!(&bytes[..2], &[0xFF, 0x25]);
        // disp32 はアドレススロット自身（from + 6）。
        assert_eq!(&bytes[2..6], &0x1006u32.to_le_bytes());
        assert_eq!(&bytes[6..], &0x9000_0000u32.to_le_bytes());
    }

    #[test]
    fn plan_simple_prologue_stops_at_patch_len() {
        // 典型的な x64 プロローグ: mov [rsp+8],rbx (5B) で 5 バイトに達する。
        let bytes = [
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
            0x48, 0x89, 0x74, 0x24, 0x10, // mov [rsp+0x10], rsi
            0x57, // push rdi
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        ];
        let plan = plan_stolen(&bytes, 0x1400_0000, 0x1400_1000, 64).unwrap();
        assert_eq!(plan.stolen_len, 5);
        assert_eq!(plan.patch_len, 5);
        assert_eq!(plan.instructions.len(), 1);
    }

    #[test]
    fn plan_accumulates_whole_instructions() {
        // push rbp (1B) + mov rbp,rsp (3B) = 4B < 5 なので次も盗む。
        let bytes = [
            0x55, // push rbp
            0x48, 0x8B, 0xEC, // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        ];
        let plan = plan_stolen(&bytes, 0x1400_0000, 0x1400_1000, 64).unwrap();
        assert_eq!(plan.stolen_len, 8);
        assert_eq!(plan.instructions.len(), 3);
    }

    #[test]
    fn plan_too_short_when_bytes_run_out() {
        assert_eq!(
            plan_stolen(&[0x55], 0x1000, 0x2000, 64),
            Err(InlineRefusal::TooShort {
                available: 1,
                needed: 5
            })
        );
        assert_eq!(
            plan_stolen(&[], 0x1000, 0x2000, 64),
            Err(InlineRefusal::TooShort {
                available: 0,
                needed: 5
            })
        );
    }

    #[test]
    fn plan_decode_failed_on_invalid_bytes() {
        // 0x06 は 64bit モードで無効。
        let bytes = [0x06, 0x06, 0x06, 0x06, 0x06, 0x06];
        assert_eq!(
            plan_stolen(&bytes, 0x1000, 0x2000, 64),
            Err(InlineRefusal::DecodeFailed)
        );
    }

    #[test]
    fn plan_invalid_bitness() {
        assert_eq!(
            plan_stolen(&[0x90; 8], 0x1000, 0x2000, 16),
            Err(InlineRefusal::InvalidBitness(16))
        );
    }

    #[test]
    fn trampoline_preserves_rip_relative_operand() {
        // mov rax,[rip+0x10] (7B)。実効アドレスは target+7+0x10。
        let target = 0x1400_0000u64;
        let bytes = [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        assert_eq!(plan.stolen_len, 7);
        let trampoline = 0x1401_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        assert!(!instrs.is_empty());
        assert!(instrs[0].is_ip_rel_memory_operand());
        // 再配置後も同じ実効アドレスを指すこと。RIP 相対では
        // memory_displacement64() が絶対アドレスを返すため、
        // ip_rel_memory_address() で比べる。
        assert_eq!(instrs[0].ip_rel_memory_address(), target + 7 + 0x10);
    }

    #[test]
    fn trampoline_widens_short_conditional_jump() {
        // je +0x10（飛び先は盗んだ範囲の外、target+0x12）/ nop x3 = 5B。
        let target = 0x1400_0000u64;
        let bytes = [0x74, 0x10, 0x90, 0x90, 0x90];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        assert_eq!(plan.stolen_len, 5);
        // トランポリンを遠方に置くと rel8 では届かない。
        let trampoline = 0x1402_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        assert_eq!(instrs[0].code(), Code::Je_rel32_64);
        assert_eq!(instrs[0].near_branch_target(), target + 0x12);
    }

    #[test]
    fn trampoline_relocates_call_to_same_target() {
        // call +0（呼び出し先は target+5 自身）。
        let target = 0x1400_0000u64;
        let bytes = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        let trampoline = 0x1402_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        assert_eq!(instrs[0].code(), Code::Call_rel32_64);
        assert_eq!(instrs[0].near_branch_target(), target + 5);
    }

    #[test]
    fn trampoline_internal_branch_stays_inside() {
        // jmp +2 (2B) / nop / nop / add rax,1 (4B) = 8B。
        // jmp の飛び先は盗んだ範囲内の target+4。
        let target = 0x1400_0000u64;
        let bytes = [0xEB, 0x02, 0x90, 0x90, 0x48, 0x83, 0xC0, 0x01];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        let trampoline = 0x1402_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        // 範囲内の飛び先はトランポリン内の対応位置へ写る。
        assert_eq!(instrs[0].near_branch_target(), trampoline + 4);
    }

    #[test]
    fn trampoline_ends_with_back_jump_to_continuation() {
        let target = 0x1400_0000u64;
        let bytes = [
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx (5B)
        ];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        let trampoline = 0x1401_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        let last = instrs.last().unwrap();
        assert_eq!(last.flow_control(), FlowControl::UnconditionalBranch);
        assert_eq!(last.near_branch_target(), target + 5);
    }

    #[test]
    fn loop_to_inside_block_stays_short() {
        // loop +1（飛び先は盗んだ範囲内の target+3）+ nop x3 = 5B。
        // 飛び先は命令と一緒に移動するため rel8 のままで正しい。
        let target = 0x1400_0000u64;
        let bytes = [0xE2, 0x01, 0x90, 0x90, 0x90];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        let trampoline = 0x1402_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        assert_eq!(instrs[0].code(), Code::Loop_rel8_64_RCX);
        assert_eq!(instrs[0].near_branch_target(), trampoline + 3);
    }

    #[test]
    fn loop_to_far_outside_is_rewritten() {
        // loop +0x10（飛び先は盗んだ範囲の外、target+0x12）+ nop x3 = 5B。
        // BlockEncoder は loop を「loop short skip; jmp rel32 target」
        // へ書き換えて遠方化する（rel8 しか持たない命令の救済）。
        let target = 0x1400_0000u64;
        let bytes = [0xE2, 0x10, 0x90, 0x90, 0x90];
        let plan = plan_stolen(&bytes, target, 0x1400_1000, 64).unwrap();
        let trampoline = 0x1402_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 64);
        // 先頭は loop のまま、書き換え後の rel32 ジャンプが元の飛び先を指す。
        assert_eq!(instrs[0].code(), Code::Loop_rel8_64_RCX);
        let jmp = instrs
            .iter()
            .find(|i| i.code() == Code::Jmp_rel32_64 && i.near_branch_target() == target + 0x12)
            .expect("rewritten rel32 jump to the loop target present");
        assert_eq!(jmp.near_branch_target(), target + 0x12);
    }

    #[test]
    fn trampoline_x86_prologue() {
        // push ebp (1B) / mov ebp,esp (2B) / sub esp,8 (3B) = 6B。
        let target = 0x1000u64;
        let bytes = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08];
        let plan = plan_stolen(&bytes, target, 0x2000, 32).unwrap();
        assert_eq!(plan.stolen_len, 6);
        let trampoline = 0x2000_0000u64;
        let code = build_trampoline(&plan, trampoline).unwrap();
        let instrs = decode_all(&code, trampoline, 32);
        assert_eq!(instrs.len(), 4); // 3 命令 + 戻りジャンプ
        let last = instrs.last().unwrap();
        assert_eq!(last.near_branch_target(), target + 6);
    }

    #[test]
    fn build_patch_matches_jump_bytes() {
        // build_patch は engine.rs が使う公開の入口で、jump_bytes の別名。
        // 近距離は E9 rel32（5 バイト）、遠距離は絶対間接ジャンプ。
        assert_eq!(
            build_patch(0x1000, 0x2000, 64),
            vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]
        );
        assert_eq!(
            build_patch(0x1000, 0x2000, 64),
            jump_bytes(0x1000, 0x2000, 64)
        );
        assert_eq!(build_patch(0x1000, 0x1_0000_1000, 64).len(), 14);
        assert_eq!(
            build_patch(0x1000, 0x1_0000_1000, 64),
            jump_bytes(0x1000, 0x1_0000_1000, 64)
        );
        assert_eq!(build_patch(0x1000, 0x9000_0000, 32).len(), 10);
        assert_eq!(
            build_patch(0x1000, 0x9000_0000, 32),
            jump_bytes(0x1000, 0x9000_0000, 32)
        );
    }

    #[test]
    fn refusal_reason_strings() {
        // Coverage へ残す短い理由文字列（全バリアント）。
        assert_eq!(
            InlineRefusal::TooShort {
                available: 2,
                needed: 5
            }
            .reason(),
            "too-short"
        );
        assert_eq!(InlineRefusal::DecodeFailed.reason(), "decode-failed");
        assert_eq!(
            InlineRefusal::Unrelocatable("x".to_string()).reason(),
            "unrelocatable"
        );
        assert_eq!(
            InlineRefusal::InvalidBitness(16).reason(),
            "invalid-bitness"
        );
    }
}
