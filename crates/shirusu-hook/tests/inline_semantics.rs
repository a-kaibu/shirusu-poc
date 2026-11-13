//! Inline Hook の命令再配置を、独立した命令デコーダ (iced-x86 Decoder) で
//! 意味的に検査する PBT。単体テストの固定ケースに加え、実関数の先頭に
//! 現れる命令 (プロローグ・RIP 相対・相対 call / jcc / jmp) を任意の順で
//! 並べ、任意の配置先へ再配置しても、次が保たれることを確かめる。
//!
//! - パッチは Detour にちょうど届く (rel32 / 絶対間接のどちらでも)。
//! - トランポリンは元の続き (target + stolen_len) へ戻る。
//! - RIP 相対オペランドの実効アドレスと、範囲外への分岐先は再配置で変わらない。
//! - 近い配置先 (±1GiB) では再配置を拒否しない。

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use proptest::prelude::*;
use shirusu_hook::inline::{
    build_patch, build_trampoline, plan_stolen, StolenPlan, PATCH_LEN_REL32,
};

#[derive(Debug, Clone)]
enum Op {
    PushRbp,
    MovRbpRsp,
    SubRspImm8(u8),
    MovRspDispRbx(u8),
    LeaRaxRip(i32),
    CallRel32(i32),
    JeRel8(i8),
    JneRel32(i32),
    Nop,
}

impl Op {
    fn bytes(&self) -> Vec<u8> {
        match *self {
            Op::PushRbp => vec![0x55],
            Op::MovRbpRsp => vec![0x48, 0x89, 0xE5],
            Op::SubRspImm8(i) => vec![0x48, 0x83, 0xEC, i],
            Op::MovRspDispRbx(d) => vec![0x48, 0x89, 0x5C, 0x24, d],
            Op::LeaRaxRip(d) => [&[0x48, 0x8D, 0x05][..], &d.to_le_bytes()].concat(),
            Op::CallRel32(d) => [&[0xE8][..], &d.to_le_bytes()].concat(),
            Op::JeRel8(d) => vec![0x74, d as u8],
            Op::JneRel32(d) => [&[0x0F, 0x85][..], &d.to_le_bytes()].concat(),
            Op::Nop => vec![0x90],
        }
    }
}

fn arb_op() -> impl Strategy<Value = Op> {
    // 変位は ±64MiB に制限する (近い配置先の再配置が必ず成功する範囲)。
    let disp = -(64 << 20)..(64 << 20);
    prop_oneof![
        Just(Op::PushRbp),
        Just(Op::MovRbpRsp),
        any::<u8>().prop_map(Op::SubRspImm8),
        any::<u8>().prop_map(Op::MovRspDispRbx),
        disp.clone().prop_map(Op::LeaRaxRip),
        disp.clone().prop_map(Op::CallRel32),
        any::<i8>().prop_map(Op::JeRel8),
        disp.prop_map(Op::JneRel32),
        Just(Op::Nop),
    ]
}

fn decode_all(code: &[u8], ip: u64) -> Vec<Instruction> {
    let mut d = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while d.can_decode() {
        out.push(d.decode());
    }
    out
}

/// トランポリン内で `to` へ制御が移る命令があるか (直接分岐、または
/// BlockEncoder が置いた RIP 相対スロット経由の間接分岐)。
fn reaches(code: &[u8], base: u64, decoded: &[Instruction], to: u64) -> bool {
    decoded.iter().any(|ins| {
        if matches!(ins.op0_kind(), OpKind::NearBranch64) && ins.near_branch_target() == to {
            return true;
        }
        if ins.is_ip_rel_memory_operand()
            && matches!(
                ins.flow_control(),
                FlowControl::IndirectBranch | FlowControl::IndirectCall
            )
        {
            let slot = ins.ip_rel_memory_address();
            if let Some(off) = slot.checked_sub(base).map(|o| o as usize) {
                if let Some(bytes) = code.get(off..off + 8) {
                    return u64::from_le_bytes(bytes.try_into().unwrap()) == to;
                }
            }
        }
        false
    })
}

fn check_patch(target: u64, detour: u64) {
    let patch = build_patch(target, detour, 64);
    let ins = Decoder::with_ip(64, &patch, target, DecoderOptions::NONE).decode();
    match ins.op0_kind() {
        OpKind::NearBranch64 => {
            assert_eq!(patch.len(), PATCH_LEN_REL32);
            assert_eq!(ins.near_branch_target(), detour);
        }
        OpKind::Memory => {
            assert!(ins.is_ip_rel_memory_operand());
            assert_eq!(ins.ip_rel_memory_address(), target + ins.len() as u64);
            assert_eq!(u64::from_le_bytes(patch[6..14].try_into().unwrap()), detour);
        }
        k => panic!("unexpected patch operand {k:?}"),
    }
}

fn check_trampoline(plan: &StolenPlan, trampoline: u64) {
    let near = trampoline.abs_diff(plan.target) < (1 << 30);
    let bytes = match build_trampoline(plan, trampoline) {
        Ok(b) => b,
        Err(e) => {
            assert!(!near, "near relocation refused: {e:?}");
            return;
        }
    };
    let decoded = decode_all(&bytes, trampoline);
    let region = plan.target..plan.target + plan.stolen_len as u64;
    assert!(
        reaches(&bytes, trampoline, &decoded, region.end),
        "trampoline must continue at target + stolen_len"
    );
    for orig in &plan.instructions {
        if orig.is_ip_rel_memory_operand() {
            let addr = orig.ip_rel_memory_address();
            assert!(
                decoded
                    .iter()
                    .any(|i| i.is_ip_rel_memory_operand() && i.ip_rel_memory_address() == addr),
                "RIP-relative operand {addr:#x} not preserved"
            );
        }
        if matches!(orig.op0_kind(), OpKind::NearBranch64) {
            let to = orig.near_branch_target();
            if !region.contains(&to) {
                assert!(
                    reaches(&bytes, trampoline, &decoded, to),
                    "branch target {to:#x} of {:?} not preserved",
                    orig.code()
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn patch_reaches_detour(target in 0x1_0000u64..0x7FFF_0000_0000, detour in 0x1_0000u64..0x7FFF_0000_0000, near in any::<bool>(), delta in -(1i64 << 30)..(1i64 << 30)) {
        let detour = if near { target.saturating_add_signed(delta).max(0x1_0000) } else { detour };
        check_patch(target, detour);
    }

    #[test]
    fn relocated_prologue_preserves_semantics(
        ops in prop::collection::vec(arb_op(), 1..8),
        target in 0x1000_0000u64..0x7FF0_0000_0000,
        tramp_delta in -(1i64 << 31)..(1i64 << 31),
        far_tramp in any::<bool>(),
        far_detour in any::<bool>(),
    ) {
        let mut code: Vec<u8> = ops.iter().flat_map(Op::bytes).collect();
        // 末尾に余白を足し、最後の命令を盗んでも続きを読めるようにする。
        code.extend_from_slice(&[0x90; 16]);
        let detour = if far_detour { target ^ 0x0000_4000_0000_0000 } else { target + 0x1000 };
        let trampoline = if far_tramp {
            target ^ 0x0000_2000_0000_0000
        } else {
            target.saturating_add_signed(tramp_delta / 2)
        };
        match plan_stolen(&code, target, detour, 64) {
            Ok(plan) => {
                prop_assert!(plan.stolen_len >= plan.patch_len);
                check_trampoline(&plan, trampoline);
            }
            // 拒否は「パッチ長より前に関数を抜ける命令がある」場合に限る。
            Err(_) => {
                let decoded = decode_all(&code, target);
                let patch_end = target + shirusu_hook::inline::patch_len_for(target, detour, 64) as u64;
                prop_assert!(decoded.iter().any(|i| i.next_ip() < patch_end
                    && matches!(i.flow_control(), FlowControl::UnconditionalBranch | FlowControl::Return
                        | FlowControl::IndirectBranch | FlowControl::Interrupt | FlowControl::Exception)));
            }
        }
    }
}
