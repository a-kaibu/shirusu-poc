//! Real capture schemas -> serialized trace -> comparison -> discriminating rule.
use shirusu_compare::compare_traces;
use shirusu_hook::com::*;
use shirusu_trace::{
    model::{EventBatch, TraceEvent},
    proto::CaptureEnvironment,
    schema::EventCapture,
    writer::FinalizationInfo,
    PayloadRef, TraceWriter,
};

fn trace(base: u64, width: u32, context: u32, clsid: Option<Guid>) -> shirusu_trace::ReadTrace {
    let mut environment = CaptureEnvironment {
        pointer_width: width,
        ..Default::default()
    };
    environment.session.session_id = 1;
    environment.session.qpc_frequency = 1000;
    let mut writer = TraceWriter::new(Vec::new(), environment).unwrap();
    for schema in com_schemas() {
        writer.register_schema(schema).unwrap();
    }
    let enter = com_factory_enter_values(&ComFactoryArgs {
        method: "CoCreateInstance",
        clsid,
        iid: Some(IID_ISHELL_LINK_W),
        context,
        outer: 0,
        server_info: 0,
        output_address: base + 100,
        clsid_address: base + 200,
        iid_address: base + 300,
    });
    let mut events = Vec::new();
    for (kind, schema_id, args) in [
        (
            1,
            COM_FACTORY_ENTER_SCHEMA_ID,
            encode_com_factory_enter(&enter).unwrap(),
        ),
        (
            2,
            COM_FACTORY_LEAVE_SCHEMA_ID,
            encode_com_factory_leave(&com_method_leave_values(0, base + 400, 0)).unwrap(),
        ),
    ] {
        events.push(TraceEvent {
            kind,
            sequence: kind as u64,
            timestamp_qpc: kind as u64,
            call_id: 1,
            parent_call_id: 0,
            api_id: COM_METHOD_API_ID,
            schema_id,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: Some(args),
            global_order: None,
        });
    }
    writer
        .write_batch(&EventBatch {
            session_id: 1,
            process_id: 1,
            raw_pid: 1,
            thread_id: 1,
            qpc_frequency: 1000,
            events,
        })
        .unwrap();
    shirusu_trace::read_trace(&writer.finish(FinalizationInfo::default()).unwrap()).unwrap()
}

#[test]
fn relocated_com_factories_compare_equal_across_pointer_widths() {
    let left = trace(0x1000, 32, 1, Some(CLSID_SHELL_LINK));
    for base in [0x2000, 0x1000_0000, 0x1234_5678_0000] {
        let right = trace(base, 64, 1, Some(CLSID_SHELL_LINK));
        let report = compare_traces(&left, &right);
        assert!(report.is_identical(), "{report:?}");
        assert!(shirusu_analysis::TraceView::build(&right).events[0]
            .to_json()
            .render()
            .contains("IShellLinkW"));
    }
    assert!(shirusu_hook::api::is_hook_schema(
        COM_FACTORY_ENTER_SCHEMA_ID
    ));
    assert!(shirusu_hook::api::is_hook_schema(
        COM_FACTORY_LEAVE_SCHEMA_ID
    ));
}

#[test]
fn factory_context_and_guid_changes_generate_discriminating_rules() {
    let left = trace(0x1000, 64, 1, Some(CLSID_SHELL_LINK));
    for right in [
        trace(0x2000, 64, 4, Some(CLSID_SHELL_LINK)),
        trace(0x3000, 64, 1, Some(IID_IUNKNOWN)),
    ] {
        let report = compare_traces(&left, &right);
        let candidate = report
            .candidates
            .iter()
            .find(|c| matches!(c.field.as_deref(), Some("context" | "clsid")))
            .unwrap();
        let spec = shirusu_probe::generate_rules(&left, &right, candidate)
            .spec
            .unwrap();
        let spec = shirusu_test::TestSpec::parse(&spec.to_json().render()).unwrap();
        assert!(shirusu_test::evaluate(&spec, &left).all_passed());
        assert!(!shirusu_test::evaluate(&spec, &right).all_passed());
    }
}

#[test]
fn unreadable_guid_is_not_a_captured_empty_identifier() {
    let trace = trace(0x1000, 64, 1, None);
    let view = shirusu_analysis::TraceView::build(&trace);
    assert_eq!(
        view.events[0].field("clsid").unwrap().capture,
        shirusu_trace::schema::ValueCapture::Unreadable
    );
}
