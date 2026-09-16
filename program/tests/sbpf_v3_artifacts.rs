#[test]
fn workspace_artifacts_target_sbpf_v3() {
    for path in [
        "../target/deploy/swig.so",
        "../target/deploy/test_program_authority.so",
    ] {
        let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{path}: {error}"));
        assert!(bytes.len() >= 64, "{path}: truncated ELF64 header");
        assert_eq!(&bytes[..4], b"\x7fELF", "{path}: missing ELF header");
        assert_eq!(bytes[4], 2, "{path}: expected ELF64");
        assert_eq!(bytes[5], 1, "{path}: expected little-endian ELF");
        let flags = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        assert_eq!(flags, 3, "{path}: rebuild with cargo build-sbf --arch v3");
    }
}
