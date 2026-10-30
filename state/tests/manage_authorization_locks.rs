use swig_state::{
    action::{manage_authorization_locks::ManageAuthorizationLocks, Actionable},
    Transmutable,
};

#[test]
fn layout_requires_nonzero_duration() {
    assert_eq!(ManageAuthorizationLocks::LEN, 8);
    assert!(ManageAuthorizationLocks::valid_layout(&10u64.to_le_bytes()).unwrap());
    assert!(!ManageAuthorizationLocks::valid_layout(&0u64.to_le_bytes()).unwrap());
    assert!(!ManageAuthorizationLocks::valid_layout(&[1u8; 7]).unwrap());
    assert!(!ManageAuthorizationLocks::valid_layout(&[1u8; 9]).unwrap());
}
