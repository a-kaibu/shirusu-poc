//! Win32 Metadata IID names. Identification does not imply method interception.
#[derive(Debug)]
pub struct ComInterfaceInfo {
    pub iid: [u8; 16],
    /// Fully qualified names, including aliases sharing the same IID.
    pub names: &'static [&'static str],
}
pub static COM_INTERFACES: &[ComInterfaceInfo] = include!("com_catalog_generated.inc");
pub fn interface_by_iid(iid: &[u8; 16]) -> Option<&'static ComInterfaceInfo> {
    COM_INTERFACES
        .binary_search_by_key(iid, |i| i.iid)
        .ok()
        .map(|i| &COM_INTERFACES[i])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_has_sorted_unique_iids_and_known_stream_identity() {
        assert!(COM_INTERFACES.len() > 1000);
        assert!(COM_INTERFACES.windows(2).all(|p| p[0].iid < p[1].iid));
        assert!(COM_INTERFACES.iter().all(|i| !i.names.is_empty()));
        let stream =
            interface_by_iid(&[12, 0, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70]).unwrap();
        assert!(stream.names.contains(&"Windows.Win32.System.Com.IStream"));
        assert!(interface_by_iid(&[255; 16]).is_none());
    }
}
