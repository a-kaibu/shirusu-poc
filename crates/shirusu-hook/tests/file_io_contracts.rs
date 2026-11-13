use shirusu_hook::api::api_by_id;

fn schemas() -> String {
    let mut out = String::new();
    for id in 1..=4 {
        let api = api_by_id(id).unwrap();
        out.push_str(&format!(
            "{:#?}\n{:#?}\n",
            api.enter_schema(),
            api.leave_schema()
        ));
    }
    out
}
#[test]
fn file_io_schema_wire_contract_is_unchanged() {
    assert_eq!(
        schemas(),
        include_str!("golden/file-io-schemas.txt").replace("\r\n", "\n")
    );
}
