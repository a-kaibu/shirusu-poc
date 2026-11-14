//! API Catalog の Schema 一覧と判定関数の不変条件。
//!
//! この crate 自身の単体テストは少なく、Schema の中身や一覧の構成を
//! 壊しても他 crate のテストでしか気付けなかった（ミューテーションテストで
//! 一覧・判定関数の変異がほぼ検出されなかった）。ここで直接確かめる。

use shirusu_api_catalog::api::{
    all_schemas, api_by_id, api_table, broad_schema, eager_schemas, handwritten_schemas,
    is_hook_schema, is_iat_only_api, is_no_return_api, HANDWRITTEN_API_TABLE, MAX_API_ID,
    NO_RETURN_API_IDS,
};
use shirusu_api_catalog::{all_trace_schemas, callback, com, eager_trace_schemas, winrt};
use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::CaptureTiming;
use std::collections::{BTreeSet, HashSet};

fn ids(v: &[SchemaDef]) -> BTreeSet<u32> {
    v.iter().map(|s| s.schema_id).collect()
}

/// API 表の外にある予約 Schema（COM・WinRT・コールバック）と、その向き。
fn reserved() -> Vec<(SchemaDef, CaptureTiming)> {
    vec![
        (com::com_method_enter_schema(), CaptureTiming::Before),
        (com::com_method_leave_schema(), CaptureTiming::After),
        (com::com_factory_enter_schema(), CaptureTiming::Before),
        (com::com_factory_leave_schema(), CaptureTiming::After),
        (
            winrt::winrt_activation_enter_schema(),
            CaptureTiming::Before,
        ),
        (winrt::winrt_activation_leave_schema(), CaptureTiming::After),
        (callback::callback_enter_schema(), CaptureTiming::Before),
        (callback::callback_leave_schema(), CaptureTiming::After),
    ]
}

#[test]
fn reserved_schemas_have_their_ids_names_and_capture_timing() {
    let expected = [
        com::COM_METHOD_ENTER_SCHEMA_ID,
        com::COM_METHOD_LEAVE_SCHEMA_ID,
        com::COM_FACTORY_ENTER_SCHEMA_ID,
        com::COM_FACTORY_LEAVE_SCHEMA_ID,
        winrt::WINRT_ACTIVATION_ENTER_SCHEMA_ID,
        winrt::WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
        callback::CALLBACK_ENTER_SCHEMA_ID,
        callback::CALLBACK_LEAVE_SCHEMA_ID,
    ];
    for ((def, timing), id) in reserved().into_iter().zip(expected) {
        assert_eq!(def.schema_id, id);
        let side = if timing == CaptureTiming::Before {
            "enter"
        } else {
            "leave"
        };
        assert!(
            def.name.ends_with(side),
            "{} is not a {side} schema",
            def.name
        );
        assert!(!def.fields.is_empty(), "{} has no fields", def.name);
        for f in &def.fields {
            assert_eq!(
                CaptureTiming::from_flags(f.flags),
                timing,
                "{}.{}",
                def.name,
                f.name
            );
        }
    }
    let mut lists = com::com_schemas();
    lists.extend(winrt::winrt_schemas());
    lists.extend(callback::callback_schemas());
    assert_eq!(
        lists,
        reserved().into_iter().map(|(d, _)| d).collect::<Vec<_>>()
    );
}

#[test]
fn com_results_carry_hresult_bits() {
    let leave = com::com_method_leave_schema();
    let names: Vec<_> = leave.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"return_i32_bits"), "{names:?}");
    assert!(names.contains(&"return_kind"), "{names:?}");
    let factory = com::com_factory_leave_schema();
    assert!(
        factory.fields.iter().any(|f| f.name.starts_with("return")),
        "{factory:?}"
    );
}

#[test]
fn every_schema_is_unique_and_named() {
    let all = all_trace_schemas();
    assert_eq!(ids(&all).len(), all.len(), "schema ids repeat");
    let names: HashSet<_> = all.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names.len(), all.len(), "schema names repeat");
    for s in &all {
        assert!(!s.name.is_empty() && s.schema_id != 0, "{s:?}");
    }
}

#[test]
fn api_schemas_follow_the_two_per_api_numbering() {
    let all = all_schemas();
    assert_eq!(all.len(), api_table().count() * 2);
    for (pair, api) in all.chunks(2).zip(api_table()) {
        assert_eq!(pair[0].schema_id, api.api_id * 2 - 1);
        assert_eq!(pair[1].schema_id, api.api_id * 2);
        assert_eq!(pair[0], api.enter_schema());
        assert_eq!(pair[1], api.leave_schema());
        assert!(pair[0].name.contains(api.function), "{}", pair[0].name);
    }
}

#[test]
fn handwritten_schemas_are_the_first_api_schemas() {
    let hand = handwritten_schemas();
    assert_eq!(hand.len(), HANDWRITTEN_API_TABLE.len() * 2);
    assert!(!hand.is_empty());
    assert_eq!(hand, all_schemas()[..hand.len()]);
}

#[test]
fn eager_schemas_are_everything_but_the_broad_tier() {
    let eager = eager_schemas();
    let broad: Vec<_> = api_table().filter(|a| is_iat_only_api(a.api_id)).collect();
    assert!(!broad.is_empty() && !eager.is_empty());
    assert_eq!(eager.len() + broad.len() * 2, all_schemas().len());
    for s in &eager {
        assert!(!is_iat_only_api(s.schema_id.div_ceil(2)), "{}", s.name);
    }
    let trace_eager = eager_trace_schemas();
    let mut expected = eager.clone();
    expected.extend(reserved().into_iter().map(|(d, _)| d));
    assert_eq!(trace_eager, expected);
    // 遅延登録分と合わせると全 Schema になる。
    let mut union = ids(&trace_eager);
    for api in &broad {
        union.insert(api.enter_schema_id());
        union.insert(api.leave_schema_id());
    }
    assert_eq!(union, ids(&all_trace_schemas()));
}

#[test]
fn broad_schema_resolves_only_broad_tier_ids() {
    let mut broad = 0;
    for api in api_table() {
        let enter = broad_schema(api.enter_schema_id());
        let leave = broad_schema(api.leave_schema_id());
        if is_iat_only_api(api.api_id) {
            broad += 1;
            assert_eq!(enter, Some(api.enter_schema()));
            assert_eq!(leave, Some(api.leave_schema()));
        } else {
            assert_eq!((enter, leave), (None, None), "{}", api.function);
        }
    }
    assert!(broad > 1000);
    assert_eq!(broad_schema(0), None);
    assert_eq!(broad_schema(com::COM_METHOD_ENTER_SCHEMA_ID), None);
}

#[test]
fn hook_schemas_are_api_and_com_schemas_only() {
    for api in api_table() {
        assert!(is_hook_schema(api.enter_schema_id()), "{}", api.function);
        assert!(is_hook_schema(api.leave_schema_id()), "{}", api.function);
    }
    for id in [
        com::COM_METHOD_ENTER_SCHEMA_ID,
        com::COM_METHOD_LEAVE_SCHEMA_ID,
        com::COM_FACTORY_ENTER_SCHEMA_ID,
        com::COM_FACTORY_LEAVE_SCHEMA_ID,
    ] {
        assert!(is_hook_schema(id), "{id}");
    }
    let max = (MAX_API_ID * 2) as u32;
    for id in [
        0,
        max + 1,
        max + 2,
        com::COM_METHOD_ENTER_SCHEMA_ID + 2,
        winrt::WINRT_ACTIVATION_ENTER_SCHEMA_ID,
        callback::CALLBACK_ENTER_SCHEMA_ID,
        u32::MAX,
    ] {
        assert!(!is_hook_schema(id), "{id}");
    }
    // ID の欠番（予約）に当たる Schema ID はフック由来ではない。
    let gap = (1..MAX_API_ID as u32)
        .find(|&id| api_by_id(id).is_none())
        .expect("api ids have reserved gaps");
    assert!(!is_hook_schema(gap * 2 - 1) && !is_hook_schema(gap * 2));
}

#[test]
fn no_return_apis_are_the_exit_family() {
    assert!(!NO_RETURN_API_IDS.is_empty());
    for &id in NO_RETURN_API_IDS {
        assert!(is_no_return_api(id), "{id}");
    }
    let exit_thread = api_table()
        .find(|a| a.function == "ExitThread")
        .expect("ExitThread in catalog");
    assert!(is_no_return_api(exit_thread.api_id));
    assert!(!is_no_return_api(1), "CreateFileW returns");
    assert!(!is_no_return_api(0));
}
