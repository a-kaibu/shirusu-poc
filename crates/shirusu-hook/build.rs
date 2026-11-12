fn main() {
    println!("cargo:rerun-if-changed=src/seh.c");
    let target = std::env::var("TARGET").unwrap();
    let host = std::env::var("HOST").unwrap();
    if target.ends_with("windows-msvc") && host.ends_with("windows-msvc") {
        cc::Build::new().file("src/seh.c").compile("shirusu_seh");
    }
    // Linux cross-target cargo check needs no object code. Native Windows
    // builds compile the SEH boundary with the target's MSVC toolchain.
}
