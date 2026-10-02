use pinocchio::program_error::ProgramError;
use swig_state::{
    authority::{
        programexec::session::{CreateProgramExecSessionAuthority, ProgramExecSessionAuthority},
        Authority,
    },
    IntoBytes, SwigStateError, Transmutable,
};

#[repr(C, align(8))]
struct Aligned([u8; 128]);

#[test]
fn creation_serializer_exposes_only_its_own_fields() {
    let create = CreateProgramExecSessionAuthority::new([1; 32], 3, [2; 40], [3; 32], 42);
    let bytes = create.into_bytes().unwrap();
    assert_eq!(bytes.len(), core::mem::size_of_val(&create));
    assert_eq!(bytes.len(), 120);
    assert_eq!(&bytes[112..120], &42u64.to_le_bytes());
}

#[test]
fn canonical_and_legacy_creation_encodings_initialize_the_same_stored_state() {
    let create = CreateProgramExecSessionAuthority::new([1; 32], 3, [2; 40], [3; 32], 42);
    let mut input = Aligned([0xff; 128]);
    input.0[..120].copy_from_slice(create.into_bytes().unwrap());
    for length in [120, 128] {
        let mut output = Aligned([0xff; 128]);
        ProgramExecSessionAuthority::set_into_bytes(&input.0[..length], &mut output.0).unwrap();
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
    let mut input = Aligned([0; 128]);
    input.0[32] = 41;
    for (input_length, output_length) in [(0, 128), (119, 128), (121, 128), (128, 127), (120, 128)]
    {
        let mut output = Aligned([0xab; 128]);
        let error = ProgramExecSessionAuthority::set_into_bytes(
            &input.0[..input_length],
            &mut output.0[..output_length],
        )
        .unwrap_err();
        assert_eq!(error, ProgramError::from(SwigStateError::InvalidRoleData));
        assert_eq!(output.0, [0xab; 128]);
    }
}
