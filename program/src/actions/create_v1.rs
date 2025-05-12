use no_padding::NoPadding;
use pinocchio::{
    msg,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use swig_assertions::*;
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, ActionLoader, Actionable},
    authority::{
        authority_type_to_length,
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1Authority},
        AuthorityType,
    },
    role::Position,
    swig::{swig_account_seeds_with_bump, swig_account_signer, Swig, SwigBuilder},
    IntoBytes, SwigStateError, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, CreateV1Accounts},
        SwigInstruction,
    },
};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct CreateV1Args {
    discriminator: SwigInstruction,
    pub authority_type: u16,
    pub authority_data_len: u16,
    pub bump: u8,
    pub num_actions: u8,
    pub id: [u8; 32],
}

impl CreateV1Args {
    pub fn new(
        id: [u8; 32],
        bump: u8,
        authority_type: AuthorityType,
        authority_data_len: u16,
        num_actions: u8,
    ) -> Self {
        Self {
            discriminator: SwigInstruction::CreateV1,
            id,
            bump,
            authority_type: authority_type as u16,
            authority_data_len,
            num_actions,
        }
    }
}

impl Transmutable for CreateV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for CreateV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

pub struct CreateV1<'a> {
    pub args: &'a CreateV1Args,
    pub authority_data: &'a [u8],
    pub actions: &'a [u8],
}

impl<'a> CreateV1<'a> {
    pub fn from_instruction_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < CreateV1Args::LEN {
            return Err(SwigError::InvalidSwigCreateInstructionDataTooShort.into());
        }
        let (args, rest) = unsafe { bytes.split_at_unchecked(CreateV1Args::LEN) };
        let args = unsafe { CreateV1Args::load_unchecked(args)? };
        let (authority_data, actions) =
            unsafe { rest.split_at_unchecked(args.authority_data_len as usize) };
        Ok(Self {
            args,
            authority_data,
            actions,
        })
    }

    pub fn get_action<T: Actionable<'a>>(&'a self) -> Result<Option<&'a T>, ProgramError> {
        ActionLoader::find_action::<T>(self.actions)
    }
}

// Helper function to extract public key bytes from authority data based on
// authority type
fn extract_public_key_from_authority_data(
    authority_type: AuthorityType,
    authority_data: &[u8],
) -> Result<&[u8], ProgramError> {
    match authority_type {
        AuthorityType::Ed25519 => {
            // For Ed25519, the authority data is directly the public key
            if authority_data.len() != 32 {
                return Err(SwigStateError::InvalidRoleData.into());
            }
            Ok(authority_data)
        },
        AuthorityType::Secp256k1 => {
            // For Secp256k1, the authority data is the uncompressed public key (64 bytes)
            // We need to get a deterministic 32-byte value - take the first 32 bytes (X
            // coordinate)
            if authority_data.len() != 64 {
                return Err(SwigStateError::InvalidRoleData.into());
            }

            // Just use the X coordinate (first 32 bytes) for the seed derivation
            Ok(&authority_data[0..32])
        },
        AuthorityType::Ed25519Session => {
            // For Ed25519Session, extract the public key from CreateEd25519SessionAuthority
            if authority_data.len() < CreateEd25519SessionAuthority::LEN {
                return Err(SwigStateError::InvalidRoleData.into());
            }
            let session_authority =
                unsafe { CreateEd25519SessionAuthority::load_unchecked(authority_data)? };
            Ok(&session_authority.public_key)
        },
        AuthorityType::Secp256k1Session => {
            // For Secp256k1Session, extract the public key from
            // CreateSecp256k1SessionAuthority
            if authority_data.len() < CreateSecp256k1SessionAuthority::LEN {
                return Err(SwigStateError::InvalidRoleData.into());
            }
            let session_authority =
                unsafe { CreateSecp256k1SessionAuthority::load_unchecked(authority_data)? };

            // Use the X coordinate (first 32 bytes) of the public key for seed derivation
            Ok(&session_authority.public_key[0..32])
        },
        _ => Err(SwigError::InvalidAuthorityType.into()),
    }
}

#[inline(always)]
pub fn create_v1(ctx: Context<CreateV1Accounts>, create: &[u8]) -> ProgramResult {
    msg!("checking if system owner");
    check_system_owner(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    msg!("checking zero balance");
    check_zero_balance(ctx.accounts.swig, SwigError::AccountNotEmptySwigAccount)?;
    msg!("attempting to create swig");

    let create_v1 = CreateV1::from_instruction_bytes(create)?;
    msg!(
        "create_v1.authority_data.len(): {:?}",
        create_v1.authority_data.len()
    );

    // Extract the public key from authority data
    let authority_type = AuthorityType::try_from(create_v1.args.authority_type)?;
    msg!("authority_type: {:?}", authority_type);
    let pubkey_bytes =
        extract_public_key_from_authority_data(authority_type, create_v1.authority_data)?;

    msg!("pubkey_bytes: {:?}", pubkey_bytes);

    msg!("check_self_pda");
    let bump = check_self_pda(
        &swig_account_seeds_with_bump(&create_v1.args.id, &[create_v1.args.bump], pubkey_bytes),
        ctx.accounts.swig.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;
    msg!("bump: {:?}", bump);

    let manage_authority_action = create_v1.get_action::<ManageAuthority>()?;
    let all_action = create_v1.get_action::<All>()?;
    if manage_authority_action.is_none() && all_action.is_none() {
        msg!("Root authority type must had one of the following actions: ManageAuthority or All");
        return Err(SwigError::InvalidAuthorityType.into());
    }
    let authority_type = AuthorityType::try_from(create_v1.args.authority_type)?;
    let authority_length = authority_type_to_length(&authority_type)?;
    let account_size = core::alloc::Layout::from_size_align(
        Swig::LEN + Position::LEN + authority_length + create_v1.actions.len(),
        core::mem::size_of::<u64>(),
    )
    .map_err(|_| SwigError::InvalidAlignment)?
    .pad_to_align()
    .size();
    let lamports_needed = Rent::get()?.minimum_balance(account_size);
    let swig = Swig::new(create_v1.args.id, bump, lamports_needed);

    CreateAccount {
        from: ctx.accounts.payer,
        to: ctx.accounts.swig,
        lamports: lamports_needed,
        space: account_size as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[swig_account_signer(&swig.id, &[swig.bump], pubkey_bytes)
        .as_slice()
        .into()])?;
    let swig_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let mut swig_builder = SwigBuilder::create(swig_data, swig)?;

    swig_builder.add_role(
        authority_type,
        create_v1.authority_data,
        create_v1.args.num_actions,
        create_v1.actions,
    )?;
    Ok(())
}
