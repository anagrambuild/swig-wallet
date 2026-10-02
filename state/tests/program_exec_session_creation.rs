use pinocchio::program_error::ProgramError;
use swig_state::{
    authority::{
        programexec::session::{CreateProgramExecSessionAuthority, ProgramExecSessionAuthority},
        Authority,
    },
    IntoBytes, SwigStateError, Transmutable,
};

#[repr(C, align(8))]
struct Aligned<const N: usize>([u8; N]);

#[test]
fn creation_serializer_exposes_only_its_own_fields() {
    let create = CreateProgramExecSessionAuthority::new([1; 32], 3, [2; 40], [3; 32], 42);
    let bytes = create.into_bytes().unwrap();
    assert_eq!(bytes.len(), core::mem::size_of_val(&create));
    assert_eq!(bytes.len(), 128);
    assert_eq!(&bytes[112..120], &42u64.to_le_bytes());
    assert_eq!(&bytes[120..128], &[0; 8]);
}

#[test]
fn reserved_creation_bytes_do_not_initialize_session_expiration() {
    let create = CreateProgramExecSessionAuthority::new([1; 32], 3, [2; 40], [3; 32], 42);
    let mut input = Aligned([0; 128]);
    input.0.copy_from_slice(create.into_bytes().unwrap());
    for reserved in [0, 0xff] {
        input.0[120..128].fill(reserved);
        let mut output = Aligned([0xff; 128]);
        ProgramExecSessionAuthority::set_into_bytes(&input.0, &mut output.0).unwrap();
        let stored = unsafe { ProgramExecSessionAuthority::load_unchecked(&output.0) }.unwrap();
        assert_eq!(stored.program_id, create.program_id);
        assert_eq!(stored.instruction_prefix_len, 3);
        assert_eq!(stored.instruction_prefix, create.instruction_prefix);
        assert_eq!(stored.session_key, create.session_key);
        assert_eq!(stored.max_session_length, 42);
        assert_eq!(stored.current_session_expiration, 0);
    }
}

#[test]
fn malformed_creation_and_output_lengths_reject_before_mutation() {
    let mut input = Aligned([0; 136]);
    for (input_length, output_length) in [
        (0, 128),
        (119, 128),
        (120, 128),
        (127, 128),
        (129, 128),
        (128, 127),
        (128, 129),
    ] {
        let mut output = Aligned([0xab; 136]);
        let error = ProgramExecSessionAuthority::set_into_bytes(
            &input.0[..input_length],
            &mut output.0[..output_length],
        )
        .unwrap_err();
        assert_eq!(error, ProgramError::from(SwigStateError::InvalidRoleData));
        assert_eq!(output.0, [0xab; 136]);
    }

    input.0[32] = 41;
    let mut output = Aligned([0xab; 128]);
    let error =
        ProgramExecSessionAuthority::set_into_bytes(&input.0[..128], &mut output.0).unwrap_err();
    assert_eq!(error, ProgramError::from(SwigStateError::InvalidRoleData));
    assert_eq!(output.0, [0xab; 128]);
}
