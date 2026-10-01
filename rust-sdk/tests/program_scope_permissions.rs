use solana_program::pubkey::Pubkey;
use swig_sdk::Permission;
use swig_state::{
    action::program_scope::ProgramScope,
    authority::{ed25519::ED25519Authority, AuthorityType},
    role::{Position, Role},
    Transmutable,
};

#[repr(align(16))]
struct AlignedActions([u8; 1024]);

#[test]
fn from_role_preserves_all_program_scopes() -> anyhow::Result<()> {
    let token_program = spl_token::ID;
    let custom_program = Pubkey::new_unique();
    let other_program = Pubkey::new_unique();
    let programs = [token_program, custom_program, other_program]
        .map(|program_id| Permission::Program { program_id });
    let scopes = [
        Permission::ProgramScope {
            program_id: token_program,
            target_account: Pubkey::new_unique(),
            numeric_type: 2,
            limit: None,
            window: None,
            balance_field_start: Some(64),
            balance_field_end: Some(72),
        },
        Permission::ProgramScope {
            program_id: custom_program,
            target_account: Pubkey::new_unique(),
            numeric_type: 1,
            limit: Some(250),
            window: None,
            balance_field_start: Some(8),
            balance_field_end: Some(12),
        },
        Permission::ProgramScope {
            program_id: custom_program,
            target_account: Pubkey::new_unique(),
            numeric_type: 2,
            limit: Some(500),
            window: Some(150),
            balance_field_start: Some(16),
            balance_field_end: Some(24),
        },
    ];

    let mut bytes = Vec::new();
    // Interleaving program actions keeps every scope payload aligned on the host.
    for (program, scope) in programs.iter().zip(&scopes) {
        for action in Permission::to_client_actions(vec![program.clone(), scope.clone()])? {
            action.write(&mut bytes)?;
        }
        assert_eq!(
            (bytes.len() - ProgramScope::LEN) % core::mem::align_of::<ProgramScope>(),
            0,
        );
    }
    let mut aligned = AlignedActions([0; 1024]);
    aligned.0[..bytes.len()].copy_from_slice(&bytes);
    let authority = ED25519Authority {
        public_key: [1; 32],
    };
    let position = Position::new(
        AuthorityType::Ed25519,
        0,
        ED25519Authority::LEN as u16,
        6,
        (Position::LEN + ED25519Authority::LEN + bytes.len()) as u32,
    );
    let role = Role {
        position: &position,
        authority: &authority,
        actions: &aligned.0[..bytes.len()],
    };
    let expected: Vec<Permission> = programs.into_iter().chain(scopes).collect();

    assert_eq!(Permission::from_role(&role)?, expected);
    Ok(())
}

#[test]
fn from_role_without_program_scopes_preserves_other_permissions() -> anyhow::Result<()> {
    let expected = vec![Permission::Program {
        program_id: Pubkey::new_unique(),
    }];
    let mut bytes = Vec::new();
    for action in Permission::to_client_actions(expected.clone())? {
        action.write(&mut bytes)?;
    }
    let mut aligned = AlignedActions([0; 1024]);
    aligned.0[..bytes.len()].copy_from_slice(&bytes);
    let authority = ED25519Authority {
        public_key: [1; 32],
    };
    let position = Position::new(
        AuthorityType::Ed25519,
        0,
        ED25519Authority::LEN as u16,
        1,
        (Position::LEN + ED25519Authority::LEN + bytes.len()) as u32,
    );
    let role = Role {
        position: &position,
        authority: &authority,
        actions: &aligned.0[..bytes.len()],
    };

    assert_eq!(Permission::from_role(&role)?, expected);
    Ok(())
}
