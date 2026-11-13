#![no_main]
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
use libfuzzer_sys::fuzz_target;
use shirusu_hook::inline::{build_patch, build_trampoline, plan_stolen, plan_with_near_relay};

fn addr(raw: &[u8], bitness: u32) -> u64 {
    let v = u64::from_le_bytes(raw.try_into().unwrap());
    // ユーザーモードの正規アドレス (x64: 47bit / x86: 32bit) に収める。
    // 端の 64KiB はパッチ・トランポリンが末尾をまたがないよう外す。
    if bitness == 64 {
        (v & 0x0000_7FFF_FFFF_FFFF).clamp(0x1_0000, 0x0000_7FFF_FFFE_0000)
    } else {
        (v & 0xFFFF_FFFF).clamp(0x1_0000, 0xFFFE_0000)
    }
}

/// パッチのバイト列が実際に detour へ飛ぶことを、独立した命令デコーダで確かめる。
fn patch_reaches(patch: &[u8], at: u64, to: u64, bitness: u32) {
    let mut d = Decoder::with_ip(bitness, patch, at, DecoderOptions::NONE);
    let ins = d.decode();
    assert!(matches!(
        ins.flow_control(),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
    ));
    match ins.op0_kind() {
        OpKind::NearBranch32 | OpKind::NearBranch64 => {
            assert_eq!(ins.near_branch_target(), to);
            assert_eq!(ins.len(), patch.len());
        }
        OpKind::Memory => {
            // jmp [slot]: スロットはパッチ直後、そこに行き先が入る。
            let slot = if bitness == 64 {
                ins.ip_rel_memory_address()
            } else {
                ins.memory_displacement64()
            };
            assert_eq!(slot, at + ins.len() as u64);
            let tail = &patch[ins.len()..];
            let dest = if bitness == 64 {
                u64::from_le_bytes(tail.try_into().unwrap())
            } else {
                u32::from_le_bytes(tail.try_into().unwrap()) as u64
            };
            assert_eq!(dest, to);
        }
        other => panic!("unexpected patch operand {other:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 25 {
        return;
    }
    let bitness = if data[0] & 1 == 0 { 64 } else { 32 };
    let target = addr(&data[1..9], bitness);
    let detour = if data[0] & 2 == 0 {
        // 近い Detour (rel32 で届く) も遠い Detour も両方探索する。
        target.wrapping_add(u64::from_le_bytes(data[9..17].try_into().unwrap()) & 0x3FFF_FFFF)
            & if bitness == 64 { u64::MAX } else { 0xFFFF_FFFF }
    } else {
        addr(&data[9..17], bitness)
    };
    let trampoline = addr(&data[17..25], bitness);
    let code = &data[25..];

    patch_reaches(
        &build_patch(target, detour, bitness),
        target,
        detour,
        bitness,
    );

    for plan in [
        plan_stolen(code, target, detour, bitness),
        plan_with_near_relay(code, target, detour, bitness),
    ]
    .into_iter()
    .flatten()
    {
        assert!(plan.patch_len <= plan.stolen_len);
        assert!(plan.stolen_len <= code.len());
        // 盗んだ命令は target から隙間なく並び、合計がちょうど stolen_len。
        let mut ip = target;
        for ins in &plan.instructions {
            assert_eq!(ins.ip(), ip);
            ip += ins.len() as u64;
        }
        assert_eq!(ip, target + plan.stolen_len as u64);
        // 最後の命令以外に、関数を抜ける命令はない (続くバイトは他の関数かもしれない)。
        for ins in &plan.instructions[..plan.instructions.len() - 1] {
            assert!(!matches!(
                ins.flow_control(),
                FlowControl::Return
                    | FlowControl::IndirectBranch
                    | FlowControl::Exception
                    | FlowControl::Interrupt
            ));
        }
        if let Ok(bytes) = build_trampoline(&plan, trampoline) {
            assert!(!bytes.is_empty());
            // 再配置後のトランポリンも命令として解読できる。
            let mut d = Decoder::with_ip(bitness, &bytes, trampoline, DecoderOptions::NONE);
            let first = d.decode();
            assert!(!first.is_invalid() || plan.instructions[0].is_invalid());
        }
    }
});
