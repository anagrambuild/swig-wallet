use core::mem::MaybeUninit;

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    log::sol_log_compute_units,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::from_str;
use swig_compact_instructions::InstructionIterator;

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SignV1Accounts},
        SwigInstruction,
    },
    AccountClassification,
};
use swig_assertions::*;
use swig_state_x::{
    action::{
        all::All, sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit,
        token_limit::TokenLimit, token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{swig_account_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};
// use swig_instructions::InstructionIterator;

pub const INSTRUCTION_SYSVAR_ACCOUNT: Pubkey =
    from_str("Sysvar1nstructions1111111111111111111111111");

#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct SignV1Args {
    instruction: SwigInstruction,
    pub authority_payload_len: u16,
    pub role_id: u32,
}

impl SignV1Args {
    pub fn new(role_id: u32, authority_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SignV1,
            role_id,
            authority_payload_len,
        }
    }
}

impl Transmutable for SignV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SignV1Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}
pub struct SignV1<'a> {
    pub args: &'a SignV1Args,
    authority_payload: &'a [u8],
    instruction_payload: &'a [u8],
}

impl<'a> SignV1<'a> {
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SignV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        let (inst, rest) = unsafe { data.split_at_unchecked(SignV1Args::LEN) };
        let args = unsafe { SignV1Args::load_unchecked(inst)? };
        let (authority_payload, instruction_payload) =
            unsafe { rest.split_at_unchecked(args.authority_payload_len as usize) };
        Ok(Self {
            args,
            authority_payload,
            instruction_payload,
        })
    }
}

#[inline(always)]
pub fn sign_v1(
    ctx: Context<SignV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    let sign_v1 = SignV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let role = Swig::get_mut_role(sign_v1.args.role_id, swig_roles)?;
    if role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role.unwrap();
    let clock = Clock::get()?;
    let slot = clock.slot;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    }
    const UNINIT_KEY: MaybeUninit<&Pubkey> = MaybeUninit::uninit();
    let mut restricted_keys: [MaybeUninit<&Pubkey>; 2] = [UNINIT_KEY; 2];
    let rkeys: &[&Pubkey] = unsafe {
        if role.position.authority_type()? == AuthorityType::Ed25519 {
            let authority_index = *sign_v1.authority_payload.get_unchecked(0) as usize;
            restricted_keys[0].write(&ctx.accounts.payer.key());
            restricted_keys[1].write(&all_accounts[authority_index].key());
            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 2)
        } else {
            restricted_keys[0].write(&ctx.accounts.payer.key());

            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 1)
        }
    };
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v1.instruction_payload,
        ctx.accounts.swig.key(),
        &rkeys,
    )?;
    let b = [swig.bump];
    let seeds = swig_account_signer(&swig.id, &b);
    let signer = seeds.as_slice();

    for ix in ix_iter {
        if let Ok(instruction) = ix {
            instruction.execute(all_accounts, ctx.accounts.swig.key(), &[signer.into()])?;
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }
    let actions = role.actions;
    if RoleMut::get_action_mut::<All>(actions, &[])?.is_some() {
        return Ok(());
    } else {
        for (index, account) in account_classifiers.iter().enumerate() {
            match account {
                AccountClassification::ThisSwig { lamports } => {
                    let current_lamports = all_accounts[index].lamports();
                    if current_lamports < swig.reserved_lamports {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedInsufficientBalance.into()
                        );
                    }
                    if lamports > &current_lamports {
                        let amount_diff = lamports - current_lamports;

                        {
                            if let Some(action) = RoleMut::get_action_mut::<SolLimit>(actions, &[])?
                            {
                                action.run(amount_diff)?;
                                continue;
                            };
                        }
                        {
                            if let Some(action) =
                                RoleMut::get_action_mut::<SolRecurringLimit>(actions, &[])?
                            {
                                action.run(amount_diff, slot)?;
                            };
                        }
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                },
                AccountClassification::SwigTokenAccount { balance } => {
                    let data =
                        unsafe { &all_accounts.get_unchecked(index).borrow_data_unchecked() };
                    let mint = unsafe { data.get_unchecked(0..32) };
                    let delegate = unsafe { data.get_unchecked(72..76) };
                    let state = unsafe { *data.get_unchecked(108) };
                    let current_token_balance = u64::from_le_bytes(unsafe {
                        data.get_unchecked(64..72)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?
                    });

                    if delegate != [0u8; 4] {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedTokenAccountDelegatePresent
                                .into(),
                        );
                    }
                    if state != 1 {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedTokenAccountNotInitialized
                                .into(),
                        );
                    }
                    if balance > &current_token_balance {
                        let mut matched = false;
                        let diff = balance - current_token_balance;
                        {
                            if let Some(action) =
                                RoleMut::get_action_mut::<TokenRecurringLimit>(actions, &mint)?
                            {
                                action.run(diff, slot)?;
                                continue;
                            };
                        }
                        {
                            if let Some(action) =
                                RoleMut::get_action_mut::<TokenLimit>(actions, &mint)?
                            {
                                action.run(diff)?;
                                matched = true;
                            };
                        }

                        if !matched {
                            return Err(
                                SwigAuthenticateError::PermissionDeniedMissingPermission.into()
                            );
                        }
                    }
                },
                _ => {},
            }
        }
    }

    Ok(())
}
