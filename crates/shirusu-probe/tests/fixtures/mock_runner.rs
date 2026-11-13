//! Controlled transport test fixture; this is not a Windows API implementation.
use std::{env, fs, path::Path, process, time::Duration};
fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 4);
    assert_eq!(args[1], "run");
    assert_eq!(args[3], "--json");
    assert!(Path::new(&args[2]).is_absolute());
    fs::OpenOptions::new().write(true).create_new(true).open("seen.marker").unwrap();
    let exe = env::current_exe().unwrap();
    let mode = exe.file_stem().unwrap().to_str().unwrap();
    if mode == "timeout" { std::thread::sleep(Duration::from_secs(30)); }
    if mode == "overflow" { print!("{}", " ".repeat(8 * 1024 * 1024 + 1)); return; }
    if mode == "malformed" { println!("{{broken"); return; }
    let spec = fs::read_to_string(&args[2]).unwrap();
    let field = |line: &str| line.split('"').nth(3).unwrap().to_owned();
    let name = field(spec.lines().find(|l| l.trim_start().starts_with("\"name\":")).unwrap());
    let calls: Vec<_> = spec.lines().filter(|l| l.trim_start().starts_with("\"call\":")).map(field).collect();
    let has_write = calls.iter().any(|c| c.ends_with("WriteFile"));
    let dry = mode == "dry";
    let mut failed = false;
    let mut rows = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        let executed = !dry && !failed;
        let read = call.ends_with("ReadFile");
        let ok = !failed && (!read || (has_write && mode != "candidate") || dry);
        let returned = if executed { "1" } else { "null" };
        let last_error = if executed { "0" } else { "null" };
        let outputs = if executed && read {
            let hex = if mode == "candidate" { "2b" } else { "2a" };
            format!("{{\"lpNumberOfBytesRead\":{},\"lpBuffer\":\"{hex}\"}}", usize::from(has_write))
        } else { "{}".into() };
        let error = if ok { "null" } else { "\"controlled mismatch or skipped\"" };
        rows.push(format!("{{\"index\":{index},\"call\":\"{call}\",\"ok\":{ok},\"executed\":{executed},\"returned\":{returned},\"last_error\":{last_error},\"outputs\":{outputs},\"outputs_truncated\":[],\"error\":{error}}}"));
        failed |= !ok;
    }
    println!("{{\"spec\":\"{name}\",\"executed\":{},\"all_ok\":{},\"steps\":[{}]}}", !dry, !failed, rows.join(","));
    process::exit(if mode == "badexit" { 2 } else { i32::from(failed) });
}
