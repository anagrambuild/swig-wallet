use swig_interface::ClientAction;
use swig_sdk::Permission;
use swig_state::{
    action::close_swig_authority::CloseSwigAuthority,
    authority::{ed25519::ED25519Authority, AuthorityType},
    role::{Position, Role},
    Transmutable,
};

#[test]
fn close_token_account_round_trips_through_client_encoding_and_stored_role() -> anyhow::Result<()> {
    let mut encoded = Vec::new();
    for action in Permission::to_client_actions(vec![Permission::CloseTokenAccount])? {
        action.write(&mut encoded)?;
    }
    assert_eq!(encoded, [28, 0, 0, 0, 8, 0, 0, 0]);
    assert_eq!(Permission::CloseTokenAccount.to_action_type(), 28);

    #[repr(align(8))]
    struct AlignedActions([u8; 8]);
    let mut actions = AlignedActions([0; 8]);
    actions.0.copy_from_slice(&encoded);
    let authority = ED25519Authority {
        public_key: [1; 32],
    };
    let position = Position::new(
        AuthorityType::Ed25519,
        1,
        ED25519Authority::LEN as u16,
        1,
        (Position::LEN + ED25519Authority::LEN + encoded.len()) as u32,
    );
    let role = Role {
        position: &position,
        authority: &authority,
        actions: &actions.0,
    };
    assert_eq!(
        Permission::from_role(&role)?,
        vec![Permission::CloseTokenAccount]
    );
    assert!(role
        .get_action::<CloseSwigAuthority>(&[])
        .unwrap()
        .is_none());

    encoded.clear();
    ClientAction::CloseSwigAuthority(CloseSwigAuthority).write(&mut encoded)?;
    assert_eq!(encoded, [20, 0, 0, 0, 8, 0, 0, 0]);
    actions.0.copy_from_slice(&encoded);
    let role = Role {
        position: &position,
        authority: &authority,
        actions: &actions.0,
    };
    assert!(!Permission::from_role(&role)?.contains(&Permission::CloseTokenAccount));
    Ok(())
}
