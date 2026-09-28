use swig_state::action::{
    program_scope::{NumericType, ProgramScope},
    Actionable,
};

#[test]
fn program_scope_matches_target_and_owner_program() {
    let target = [1u8; 32];
    let program = [2u8; 32];
    let scope = ProgramScope::new_limit(program, target, 100u64, NumericType::U64);

    let mut match_data = [0u8; 64];
    match_data[..32].copy_from_slice(&target);
    match_data[32..].copy_from_slice(&program);
    assert!(scope.match_data(&match_data));

    match_data[32..].copy_from_slice(&[3u8; 32]);
    assert!(!scope.match_data(&match_data));
    match_data[32..].copy_from_slice(&program);
    match_data[..32].copy_from_slice(&[4u8; 32]);
    assert!(!scope.match_data(&match_data));
    assert!(!scope.match_data(&target));
}
