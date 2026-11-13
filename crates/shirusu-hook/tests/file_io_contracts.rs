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

fn captures() -> String {
    use shirusu_hook::capture::*;
    let mut memory = MapMemory::new();
    memory.write_u16s(0x1000, &[b'x' as u16, 0]);
    memory.write(0x2000, b"abc");
    memory.write_u32(0x3000, 3);
    let mut out = String::new();
    let mut add = |name: &str, id, leave, values: Vec<shirusu_trace::schema::CapturedValue>| {
        let api = api_by_id(id).unwrap();
        let encoded = if leave {
            encode_leave(api, &values)
        } else {
            encode_enter(api, &values)
        }
        .unwrap();
        out.push_str(name);
        out.push(':');
        for byte in encoded {
            out.push_str(&format!("{byte:02x}"));
        }
        out.push('\n');
    };
    add(
        "create-enter",
        1,
        false,
        create_file_w_enter(&memory, 0x1000, 0xc0000000, 3, 0, 1, 0x80, 0),
    );
    add(
        "create-unreadable",
        1,
        false,
        create_file_w_enter(&memory, 0x9999, 0, 0, 0, 1, 0, 0),
    );
    for handle in [42, u32::MAX as u64, u64::MAX] {
        add(
            &format!("create-leave-{handle}"),
            1,
            true,
            create_file_w_leave(handle, 5, 3),
        );
    }
    add("read-enter", 2, false, read_file_enter(42, 0x2000, 3, 0));
    for (name, success, requested, count_addr, overlapped) in [
        ("read-success", 1, 3, 0x3000, false),
        ("read-noncanonical-bool", -1, 3, 0x3000, false),
        ("read-count-exceeds-capacity", 1, 2, 0x3000, false),
        ("read-failure", 0, 3, 0x3000, false),
        ("read-null-count", 1, 3, 0, false),
        ("read-unreadable-count", 1, 3, 0x9999, false),
        ("read-pending", 0, 3, 0x3000, true),
        ("read-overlapped-success", 1, 3, 0x3000, true),
    ] {
        add(
            name,
            2,
            true,
            read_file_leave(
                &memory, success, 0x2000, requested, count_addr, overlapped, 997,
            ),
        );
    }
    add(
        "write-enter",
        3,
        false,
        write_file_enter(&memory, 42, 0x2000, 3, 0),
    );
    add(
        "write-unreadable",
        3,
        false,
        write_file_enter(&memory, 42, 0x9999, 3, 0),
    );
    for (name, success, count_addr, overlapped) in [
        ("write-success", 1, 0x3000, false),
        ("write-failure", 0, 0x3000, false),
        ("write-null-count", 1, 0, false),
        ("write-pending", 0, 0x3000, true),
    ] {
        add(
            name,
            3,
            true,
            write_file_leave(&memory, success, count_addr, overlapped, 997),
        );
    }
    add("close-enter", 4, false, close_handle_enter(42));
    add("close-success", 4, true, close_handle_leave(1, 5));
    add("close-failure", 4, true, close_handle_leave(0, 5));
    out
}

#[test]
fn file_io_capture_wire_contract_is_unchanged() {
    assert_eq!(
        captures(),
        include_str!("golden/file-io-captures.txt").replace("\r\n", "\n")
    );
}

include!("file_io_boundaries_generated.inc");

#[test]
fn generated_buffer_boundaries_never_read_outside_caller_capacity() {
    use shirusu_hook::capture::{self, MemoryReader, MAX_BUFFER_BYTES};
    use shirusu_trace::schema::{TypedValue, ValueCapture};
    use std::cell::Cell;
    struct Memory {
        capacity: u32,
        transferred: u32,
        buffer_reads: Cell<usize>,
    }
    impl MemoryReader for Memory {
        fn read_exact(&self, address: u64, bytes: &mut [u8]) -> bool {
            match address {
                0x3000 => {
                    bytes.copy_from_slice(&self.transferred.to_le_bytes());
                }
                0x2000 => {
                    assert!(bytes.len() <= self.capacity as usize);
                    assert!(bytes.len() <= MAX_BUFFER_BYTES);
                    self.buffer_reads.set(self.buffer_reads.get() + 1);
                    bytes.fill(42);
                }
                _ => panic!("unexpected contract memory address"),
            }
            true
        }
    }
    for requested in BUFFER_LENGTHS {
        for transferred in BUFFER_LENGTHS {
            let memory = Memory {
                capacity: requested,
                transferred,
                buffer_reads: Cell::new(0),
            };
            let values = capture::read_file_leave(&memory, 1, 0x2000, requested, 0x3000, false, 5);
            assert_eq!(values[1].value, TypedValue::U32(transferred));
            if transferred > requested {
                assert_eq!(values[2].capture, ValueCapture::Unsupported);
                assert_eq!(memory.buffer_reads.get(), 0);
            } else {
                assert_eq!(
                    values[2].capture,
                    if transferred as usize > MAX_BUFFER_BYTES {
                        ValueCapture::Truncated
                    } else {
                        ValueCapture::Captured
                    }
                );
                assert_eq!(
                    values[2].value,
                    TypedValue::Bytes(vec![42; (transferred as usize).min(MAX_BUFFER_BYTES)])
                );
            }
        }
        let memory = Memory {
            capacity: requested,
            transferred: 0,
            buffer_reads: Cell::new(0),
        };
        let values = capture::write_file_enter(&memory, 42, 0x2000, requested, 0);
        assert_eq!(
            values[1].value,
            TypedValue::Bytes(vec![42; (requested as usize).min(MAX_BUFFER_BYTES)])
        );
        assert_eq!(
            values[1].capture,
            if requested as usize > MAX_BUFFER_BYTES {
                ValueCapture::Truncated
            } else {
                ValueCapture::Captured
            }
        );
    }
    struct NoMemory;
    impl MemoryReader for NoMemory {
        fn read_exact(&self, _: u64, _: &mut [u8]) -> bool {
            panic!("asynchronous output is not ready")
        }
    }
    for requested in BUFFER_LENGTHS {
        let read = capture::read_file_leave(&NoMemory, 1, 0x2000, requested, 0x3000, true, 0);
        assert_eq!(read[1].capture, ValueCapture::Unsupported);
        assert_eq!(read[2].capture, ValueCapture::Unsupported);
        let write = capture::write_file_leave(&NoMemory, 1, 0x3000, true, 0);
        assert_eq!(write[1].capture, ValueCapture::Unsupported);
    }
}
