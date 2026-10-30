use pinocchio::program_error::ProgramError;
use swig_interface::instruction_data as client;
use swig_program::actions as program;
use swig_state::{authority::AuthorityType, IntoBytes};

// Compare the production client's complete fixed headers against the local
// program, including discriminants, explicit padding, field order and alignment.
macro_rules! check_header {
    ($module:ident, $name:ident, $($arg:expr),+ $(,)?) => {{
        let client = client::$name::new($($arg),+);
        let program = program::$module::$name::new($($arg),+);
        assert_eq!(core::mem::size_of_val(&client), core::mem::size_of_val(&program));
        assert_eq!(core::mem::align_of_val(&client), core::mem::align_of_val(&program));
        assert_eq!(client.into_bytes()?, program.into_bytes()?, stringify!($name));
    }};
}

#[test]
fn instruction_headers_match_program() -> Result<(), ProgramError> {
    for role in [0, 0x0102_0304, u32::MAX] {
        for length in [0, 0x0102, u16::MAX] {
            for amount in [0, 9_007_199_254_740_993, u64::MAX] {
                check_header!(
                    create_v1,
                    CreateV1Args,
                    [0x11; 32],
                    254,
                    AuthorityType::Ed25519,
                    length,
                    253
                );
                check_header!(
                    add_authority_v1,
                    AddAuthorityV1Args,
                    role,
                    AuthorityType::Secp256r1Session,
                    length,
                    length.wrapping_add(1),
                    255
                );
                check_header!(
                    remove_authority_v1,
                    RemoveAuthorityV1Args,
                    role,
                    role.wrapping_add(1),
                    length
                );
                check_header!(
                    update_authority_v1,
                    UpdateAuthorityV1Args,
                    role,
                    role.wrapping_add(1),
                    length,
                    255
                );
                check_header!(
                    replace_authority_v1,
                    ReplaceAuthorityV1Args,
                    role,
                    role.wrapping_add(1),
                    length
                );
                check_header!(
                    create_session_v1,
                    CreateSessionV1Args,
                    role,
                    amount,
                    [0x22; 32]
                );
                check_header!(sign_v2, SignV2Args, role, length);
                check_header!(close_swig_v1, CloseSwigV1Args, role);
                check_header!(
                    close_token_account_v1,
                    CloseTokenAccountV1Args,
                    role,
                    length
                );
                check_header!(set_rent_claimer_v1, SetRentClaimerV1Args, role, [0x33; 32]);
                check_header!(transfer_assets_v1, TransferAssetsV1Args, role);
                check_header!(create_sub_account_v1, CreateSubAccountV1Args, role, 254);
                check_header!(create_sub_account_v2, CreateSubAccountV2Args, role);
                check_header!(
                    close_sub_account_v1,
                    CloseSubAccountV1Args,
                    role,
                    role.wrapping_add(1)
                );
                check_header!(
                    close_sub_account_v2,
                    CloseSubAccountV2Args,
                    role,
                    role.wrapping_add(1)
                );
                check_header!(sub_account_sign_v1, SubAccountSignV1Args, role, length);
                check_header!(
                    sub_account_sign_v2,
                    SubAccountSignV2Args,
                    role,
                    role.wrapping_add(1),
                    length
                );
                for enabled in [false, true] {
                    check_header!(
                        toggle_sub_account_v1,
                        ToggleSubAccountV1Args,
                        role,
                        role.wrapping_add(1),
                        enabled
                    );
                    check_header!(
                        toggle_sub_account_v2,
                        ToggleSubAccountV2Args,
                        role,
                        role.wrapping_add(1),
                        enabled
                    );
                }
                check_header!(
                    withdraw_from_sub_account_v1,
                    WithdrawFromSubAccountV1Args,
                    role,
                    amount
                );
                check_header!(
                    withdraw_from_sub_account_v2,
                    WithdrawFromSubAccountV2Args,
                    role,
                    role.wrapping_add(1),
                    amount
                );
            }
        }
    }
    Ok(())
}

#[test]
fn program_identity_and_proof_constants_match() {
    assert_eq!(swig_interface::PROGRAM_ID, swig_program::ID);
    assert_eq!(
        client::REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR,
        program::replace_authority_v1::REPLACE_AUTHORITY_PROOF_V1_DISCRIMINATOR
    );
    assert_eq!(
        client::REPLACE_AUTHORITY_PROOF_V1_DOMAIN,
        program::replace_authority_v1::REPLACE_AUTHORITY_PROOF_V1_DOMAIN
    );
    assert_eq!(
        client::SwigInstruction::CreateReservedV1 as u16,
        swig_program::instruction::SwigInstruction::CreateReservedV1 as u16
    );
    for (client, program) in [
        (
            client::AuthorityUpdateOperation::ReplaceAll,
            program::update_authority_v1::AuthorityUpdateOperation::ReplaceAll,
        ),
        (
            client::AuthorityUpdateOperation::AddActions,
            program::update_authority_v1::AuthorityUpdateOperation::AddActions,
        ),
        (
            client::AuthorityUpdateOperation::RemoveActionsByType,
            program::update_authority_v1::AuthorityUpdateOperation::RemoveActionsByType,
        ),
        (
            client::AuthorityUpdateOperation::RemoveActionsByIndex,
            program::update_authority_v1::AuthorityUpdateOperation::RemoveActionsByIndex,
        ),
    ] {
        assert_eq!(client as u8, program as u8);
    }
}

#[test]
fn instruction_discriminants_match_program() {
    for (client, program) in [
        (
            client::SwigInstruction::CreateV1,
            swig_program::instruction::SwigInstruction::CreateV1,
        ),
        (
            client::SwigInstruction::AddAuthorityV1,
            swig_program::instruction::SwigInstruction::AddAuthorityV1,
        ),
        (
            client::SwigInstruction::RemoveAuthorityV1,
            swig_program::instruction::SwigInstruction::RemoveAuthorityV1,
        ),
        (
            client::SwigInstruction::UpdateAuthorityV1,
            swig_program::instruction::SwigInstruction::UpdateAuthorityV1,
        ),
        (
            client::SwigInstruction::DeprecatedSignV1,
            swig_program::instruction::SwigInstruction::DeprecatedSignV1,
        ),
        (
            client::SwigInstruction::CreateSessionV1,
            swig_program::instruction::SwigInstruction::CreateSessionV1,
        ),
        (
            client::SwigInstruction::CreateSubAccountV1,
            swig_program::instruction::SwigInstruction::CreateSubAccountV1,
        ),
        (
            client::SwigInstruction::WithdrawFromSubAccountV1,
            swig_program::instruction::SwigInstruction::WithdrawFromSubAccountV1,
        ),
        (
            client::SwigInstruction::SubAccountSignV1,
            swig_program::instruction::SwigInstruction::SubAccountSignV1,
        ),
        (
            client::SwigInstruction::ToggleSubAccountV1,
            swig_program::instruction::SwigInstruction::ToggleSubAccountV1,
        ),
        (
            client::SwigInstruction::SignV2,
            swig_program::instruction::SwigInstruction::SignV2,
        ),
        (
            client::SwigInstruction::MigrateToWalletAddressV1,
            swig_program::instruction::SwigInstruction::MigrateToWalletAddressV1,
        ),
        (
            client::SwigInstruction::TransferAssetsV1,
            swig_program::instruction::SwigInstruction::TransferAssetsV1,
        ),
        (
            client::SwigInstruction::CloseTokenAccountV1,
            swig_program::instruction::SwigInstruction::CloseTokenAccountV1,
        ),
        (
            client::SwigInstruction::CloseSwigV1,
            swig_program::instruction::SwigInstruction::CloseSwigV1,
        ),
        (
            client::SwigInstruction::ReplaceAuthorityV1,
            swig_program::instruction::SwigInstruction::ReplaceAuthorityV1,
        ),
        (
            client::SwigInstruction::SetRentClaimerV1,
            swig_program::instruction::SwigInstruction::SetRentClaimerV1,
        ),
        (
            client::SwigInstruction::CreateSubAccountV2,
            swig_program::instruction::SwigInstruction::CreateSubAccountV2,
        ),
        (
            client::SwigInstruction::ToggleSubAccountV2,
            swig_program::instruction::SwigInstruction::ToggleSubAccountV2,
        ),
        (
            client::SwigInstruction::SubAccountSignV2,
            swig_program::instruction::SwigInstruction::SubAccountSignV2,
        ),
        (
            client::SwigInstruction::WithdrawFromSubAccountV2,
            swig_program::instruction::SwigInstruction::WithdrawFromSubAccountV2,
        ),
        (
            client::SwigInstruction::CloseSubAccountV1,
            swig_program::instruction::SwigInstruction::CloseSubAccountV1,
        ),
        (
            client::SwigInstruction::CloseSubAccountV2,
            swig_program::instruction::SwigInstruction::CloseSubAccountV2,
        ),
        (
            client::SwigInstruction::CreateReservedV1,
            swig_program::instruction::SwigInstruction::CreateReservedV1,
        ),
    ] {
        assert_eq!(client as u16, program as u16);
    }
}
