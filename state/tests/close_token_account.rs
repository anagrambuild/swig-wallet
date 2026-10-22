use swig_state::{
    action::{
        close_swig_authority::CloseSwigAuthority, close_token_account::CloseTokenAccount, Action,
        ActionLoader, Permission,
    },
    IntoBytes, SwigStateError, Transmutable,
};

#[test]
fn close_token_account_wire_type_rejects_unknown_discriminants_and_payloads() {
    assert_eq!(Permission::try_from(20), Ok(Permission::CloseSwigAuthority));
    assert_eq!(Permission::try_from(26), Ok(Permission::SubAccountV2Toggle));
    assert_eq!(Permission::try_from(28), Ok(Permission::CloseTokenAccount));
    for value in [27, 29, u16::MAX] {
        assert_eq!(
            Permission::try_from(value),
            Err(SwigStateError::PermissionLoadError.into()),
        );
    }
    assert_eq!(
        ActionLoader::validate_layout(Permission::CloseTokenAccount, &[]),
        Ok(true)
    );
    assert_eq!(
        ActionLoader::validate_layout(Permission::CloseTokenAccount, &[0; 8]),
        Ok(false)
    );
}

#[test]
fn close_permissions_are_distinct_and_each_nonrepeatable() {
    #[repr(align(8))]
    struct AlignedActions([u8; Action::LEN * 2]);

    let mut bytes = AlignedActions([0; Action::LEN * 2]);
    let token = Action::new(Permission::CloseTokenAccount, 0, Action::LEN as u32);
    bytes.0[..Action::LEN].copy_from_slice(token.into_bytes().unwrap());
    assert!(
        ActionLoader::find_action::<CloseTokenAccount>(&bytes.0[..Action::LEN])
            .unwrap()
            .is_some()
    );
    assert!(
        ActionLoader::find_action::<CloseSwigAuthority>(&bytes.0[..Action::LEN])
            .unwrap()
            .is_none()
    );

    let duplicate = Action::new(Permission::CloseTokenAccount, 0, (Action::LEN * 2) as u32);
    bytes.0[Action::LEN..].copy_from_slice(duplicate.into_bytes().unwrap());
    assert_eq!(
        ActionLoader::validate_v2_actions(&bytes.0, 0),
        Err(SwigStateError::DuplicateNonRepeatableAction.into()),
    );

    let swig = Action::new(Permission::CloseSwigAuthority, 0, (Action::LEN * 2) as u32);
    bytes.0[Action::LEN..].copy_from_slice(swig.into_bytes().unwrap());
    assert_eq!(ActionLoader::validate_v2_actions(&bytes.0, 0), Ok(()));
    assert!(ActionLoader::find_action::<CloseSwigAuthority>(&bytes.0)
        .unwrap()
        .is_some());
}
