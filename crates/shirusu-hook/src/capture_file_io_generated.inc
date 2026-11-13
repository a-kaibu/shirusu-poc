// Generated from file-io-contracts.toml; do not edit.
pub const MAX_BUFFER_BYTES: usize = 4096;
pub const MAX_STRING_UNITS: usize = 1024;
#[allow(clippy::too_many_arguments)]
pub fn create_file_w_enter(mem: &dyn MemoryReader, a0: u64, a1: u32, a2: u32, a3: u64, a4: u32, a5: u32, a6: u64) -> Vec<CapturedValue> {
    let v0 = read_utf16_string(mem, a0);
    let v1 = u32v(a1);
    let v2 = u32v(a2);
    let v3 = u64v(a3);
    let v4 = u32v(a4);
    let v5 = u32v(a5);
    let v6 = u64v(a6);
    vec![v0, v1, v2, v3, v4, v5, v6]
}
#[allow(clippy::too_many_arguments)]
pub fn create_file_w_leave(a0: u64, a1: u32) -> Vec<CapturedValue> {
    let v0 = u64v(a0);
    let v1 = last_error_value(crate::api::HANDWRITTEN_API_TABLE[0].last_error_meaning, a0, a1);
    vec![v0, v1]
}
#[allow(clippy::too_many_arguments)]
pub fn read_file_enter(a0: u64, a1: u64, a2: u32, a3: u64) -> Vec<CapturedValue> {
    let v0 = u64v(a0);
    let v1 = u64v(a1);
    let v2 = u32v(a2);
    let v3 = u64v(a3);
    vec![v0, v1, v2, v3]
}
#[allow(clippy::too_many_arguments)]
pub fn read_file_leave(mem: &dyn MemoryReader, a0: i32, a1: u64, a2: u32, a3: u64, a4: bool, a5: u32) -> Vec<CapturedValue> {
    let v0 = i32v(a0);
    let v1 = read_io_count(mem, a3, a4);
    let v2 = read_io_output(mem, a0, a1, a2, &v1, a4);
    let v3 = last_error_value(crate::api::HANDWRITTEN_API_TABLE[1].last_error_meaning, a0 as u64, a5);
    vec![v0, v1, v2, v3]
}
#[allow(clippy::too_many_arguments)]
pub fn write_file_enter(mem: &dyn MemoryReader, a0: u64, a1: u64, a2: u32, a3: u64) -> Vec<CapturedValue> {
    let v0 = u64v(a0);
    let v1 = read_buffer(mem, a1, a2 as usize);
    let v2 = u32v(a2);
    let v3 = u64v(a3);
    vec![v0, v1, v2, v3]
}
#[allow(clippy::too_many_arguments)]
pub fn write_file_leave(mem: &dyn MemoryReader, a0: i32, a1: u64, a2: bool, a3: u32) -> Vec<CapturedValue> {
    let v0 = i32v(a0);
    let v1 = read_io_count(mem, a1, a2);
    let v2 = last_error_value(crate::api::HANDWRITTEN_API_TABLE[2].last_error_meaning, a0 as u64, a3);
    vec![v0, v1, v2]
}
#[allow(clippy::too_many_arguments)]
pub fn close_handle_enter(a0: u64) -> Vec<CapturedValue> {
    let v0 = u64v(a0);
    vec![v0]
}
#[allow(clippy::too_many_arguments)]
pub fn close_handle_leave(a0: i32, a1: u32) -> Vec<CapturedValue> {
    let v0 = i32v(a0);
    let v1 = last_error_value(crate::api::HANDWRITTEN_API_TABLE[3].last_error_meaning, a0 as u64, a1);
    vec![v0, v1]
}
