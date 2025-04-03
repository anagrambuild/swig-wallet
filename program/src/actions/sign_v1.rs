use pinocchio::{
    account_info::AccountInfo,
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
        Authenticatable, SwigInstruction,
    },
    AccountClassification,
};
use swig_assertions::*;
use swig_state_x::{
    action::{
        all::All, sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit,
        token_limit::TokenLimit, token_recurring_limit::TokenRecurringLimit,
    },
    authority::{Authority, AuthorityType},
    swig::{swig_account_signer, Swig, SwigWithRolesMut},
    Discriminator, IntoBytes, Transmutable, TransmutableMut,
};
// use swig_instructions::InstructionIterator;

pub const INSTRUCTION_SYSVAR_ACCOUNT: Pubkey =
    from_str("Sysvar1nstructions1111111111111111111111111");

static_assertions::const_assert!(core::mem::size_of::<SignV1Args>() % 8 == 0);
#[repr(C)]
#[derive(Debug)]
pub struct SignV1Args {
    instruction: SwigInstruction,
    pub role_id: u32,
    pub authority_payload_len: u16,
    pub instruction_payload_len: u16,
    _padding: u8,
}

impl SignV1Args {
    pub fn new(role_id: u32, authority_payload_len: u16, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SignV1,
            role_id,
            authority_payload_len,
            instruction_payload_len,
            _padding: 0,
        }
    }
}

impl Transmutable for SignV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl<'a> IntoBytes<'a> for SignV1Args {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
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
        let (inst, rest) = data.split_at(SignV1Args::LEN);
        let args = unsafe { SignV1Args::load_unchecked(inst)? };
        let (authority_payload, instruction_payload) =
            rest.split_at(args.authority_payload_len as usize);
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
    check_stack_height(1, SwigError::Cpi)?; // todo think about if this is necessary
    check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    let sign_v1 = SignV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if swig_account_data[0] != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let swig = SwigWithRolesMut::from_bytes(swig_account_data)?;
    let role_position = swig.lookup_role(sign_v1.args.role_id)?;
    if role_position.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role_position = role_position.unwrap();
    let authority = swig.get_authority(&role_position)?;
    let clock = Clock::get()?;
    let slot = clock.slot;
    if authority.session_based() {
        authority.authenticate_session(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    } else {
        authority.authenticate(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    }

    let (restricted_keys, len): ([&Pubkey; 2], usize) =
        if role_position.position.authority_type()? == AuthorityType::Ed25519 {
            (
                [ctx.accounts.payer.key(), ctx.remaining_accounts[0].key()],
                2,
            )
        } else {
            ([ctx.accounts.payer.key(), ctx.accounts.payer.key()], 1)
        };
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v1.instruction_payload,
        ctx.accounts.swig.key(),
        &restricted_keys[0..len],
    )?;
    let b = [swig.state.bump];
    let signer = swig_account_signer(&swig.state.id, &b);
    for ix in ix_iter {
        if let Ok(instruction) = ix {
            instruction.execute(
                all_accounts,
                ctx.accounts.swig.key(),
                &[signer.as_slice().into()],
            )?;
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }
    if swig.get_action::<All>(&role_position, &[])?.is_some() {
        return Ok(());
    }
    for (index, account) in account_classifiers.iter().enumerate() {
        match account {
            AccountClassification::ThisSwig { lamports } => {
                if lamports > &all_accounts[index].lamports() {
                    let amount_diff = lamports - all_accounts[index].lamports();
                    let sol_actions = (
                        swig.get_action::<SolRecurringLimit>(&role_position, &[])?,
                        swig.get_action::<SolLimit>(&role_position, &[])?,
                    );
                    match sol_actions {
                        (Some(recurring_action), Some(limit_action)) => {
                            recurring_action.run(amount_diff, slot)?;
                            limit_action.run(amount_diff)?;
                        },
                        (Some(recurring_action), None) => {
                            recurring_action.run(amount_diff, slot)?;
                        },
                        (None, Some(limit_action)) => {
                            limit_action.run(amount_diff)?;
                        },
                        _ => {
                            return Err(SwigError::PermissionDeniedMissingPermission.into());
                        },
                    }
                }
            },
            AccountClassification::SwigTokenAccount { balance } => {
                let data = unsafe { &all_accounts[index].borrow_data_unchecked() };
                let mint = &data[0..32];
                let delegate = &data[72..76];
                let state = &data[108];
                let current_token_balance = u64::from_le_bytes(
                    data[64..72]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidAccountData)?,
                );

                if delegate != [0u8; 4] {
                    return Err(SwigError::PermissionDeniedTokenAccountDelegatePresent.into());
                }
                if *state != 1 {
                    return Err(SwigError::PermissionDeniedTokenAccountNotInitialized.into());
                }
                if balance > &current_token_balance {
                    let token_actions = (
                        swig.get_action::<TokenRecurringLimit>(&role_position, mint)?,
                        swig.get_action::<TokenLimit>(&role_position, mint)?,
                    );
                    let diff = balance - current_token_balance;
                    match token_actions {
                        (Some(recurring_action), Some(limit_action)) => {
                            recurring_action.run(diff, slot)?;
                            limit_action.run(diff)?;
                        },
                        (Some(recurring_action), None) => {
                            recurring_action.run(diff, slot)?;
                        },
                        (None, Some(limit_action)) => {
                            limit_action.run(diff)?;
                        },
                        (None, None) => {
                            return Err(SwigError::PermissionDeniedMissingPermission.into());
                        },
                    }
                }
            },
            _ => {},
        }
    }

    Ok(())
}

// sign_v1.authenticate(all_accounts, &role)?;
// for ix in ix_iter {
//     if let Ok(instruction) = ix {
//         instruction.execute(
//             all_accounts,
//             ctx.accounts.swig.key(),
//             &[signer.as_slice().into()],
//         )?;
//         msg!("Instruction executed");
//     } else {
//         return Err(SwigError::InstructionError(ix.err().unwrap()).into());
//     }
// }
// let all = role.actions.iter().any(|action| match action {
//     Action::All => true,
//     _ => false,
// });
// if !all {
//     for (index, account) in account_classifiers.iter().enumerate() {
//         let current_account = &all_accounts[index];
//         match account {
//             AccountClassification::ThisSwig { lamports } => {
//                 if lamports > &current_account.lamports() {
//                     let amount_diff = lamports - current_account.lamports();
//                     if let Some(action) = role.actions.iter_mut().find(|action| match action {
//                         Action::Sol { .. } => true,
//                         _ => false,
//                     }) {
//                         *action = match action {
//                             Action::Sol {
//                                 action: SolAction::All,
//                             } => Ok(Action::Sol {
//                                 action: SolAction::All,
//                             }),
//                             Action::Sol {
//                                 action: SolAction::Manage(amount),
//                             } => {
//                                 if *amount >= amount_diff {
//                                     Ok(Action::Sol {
//                                         action: SolAction::Manage(*amount - amount_diff),
//                                     })
//                                 } else {
//                                     Err(SwigError::PermissionDenied(
//                                         "Sol move exceeds the amount authorized",
//                                     ))
//                                 }
//                             },
//                             _ => Err(SwigError::PermissionDenied(
//                                 "Sol cannot be moved with this role",
//                             )),
//                         }?;
//                     } else {
//                         return Err(SwigError::PermissionDenied(
//                             "Sol cannot be moved with this role",
//                         )
//                         .into());
//                     }
//                 }
//             },
//             AccountClassification::SwigTokenAccount { balance } => {
//                 // Allow account closure if the token account is empty
//                 let data = unsafe { current_account.borrow_mut_data_unchecked() };
//                 let mint = &data[0..32];
//                 let delegate = &data[72..76];
//                 let state = &data[108];
//                 if delegate != [0u8; 4] {
//                     return Err(SwigError::PermissionDenied(
//                         "Token account cannot be have delegate",
//                     )
//                     .into());
//                 }
//                 if *state != 1 {
//                     return Err(SwigError::PermissionDenied(
//                         "Token account must be initialized",
//                     )
//                     .into());
//                 }
//                 let current_token_balance = u64::from_le_bytes(
//                     data[64..72]
//                         .try_into()
//                         .map_err(|_| ProgramError::InvalidAccountData)?,
//                 );
//                 if balance != &current_token_balance {
//                     let amount_diff = balance - current_token_balance;
//                     if let Some(action) = role.actions.iter_mut().find(|action| match action {
//                         Action::Token { key, .. } if key == &mint => true,
//                         Action::Tokens { .. } => true,
//                         _ => false,
//                     }) {
//                         *action = match action {
//                             Action::Token {
//                                 key,
//                                 action: TokenAction::All,
//                             } => Ok(Action::Token {
//                                 key: *key,
//                                 action: TokenAction::All,
//                             }),
//                             Action::Token {
//                                 key,
//                                 action: TokenAction::Manage(amount),
//                             } => {
//                                 if *amount <= amount_diff {
//                                     Ok(Action::Token {
//                                         key: *key,
//                                         action: TokenAction::Manage(*amount - amount_diff),
//                                     })
//                                 } else {
//                                     Err(SwigError::PermissionDenied(
//                                         "Token move exceeds the amount authorized",
//                                     ))
//                                 }
//                             },
//                             Action::Tokens {
//                                 action: TokenAction::All,
//                             } => Ok(Action::Tokens {
//                                 action: TokenAction::All,
//                             }),
//                             Action::Tokens {
//                                 action: TokenAction::Manage(amount),
//                             } => {
//                                 if *amount <= amount_diff {
//                                     Ok(Action::Tokens {
//                                         action: TokenAction::Manage(*amount - amount_diff),
//                                     })
//                                 } else {
//                                     Err(SwigError::PermissionDenied(
//                                         "Token move exceeds the amount authorized",
//                                     ))
//                                 }
//                             },
//                             _ => Err(SwigError::PermissionDenied(
//                                 "Token cannot be moved with this role",
//                             )),
//                         }?;
//                     } else {
//                         return Err(SwigError::PermissionDenied(
//                             "Token cannot be moved with this role",
//                         )
//                         .into());
//                     }
//                 }
//             },
//             _ => {},
//         }
//     }
//     role.serialize(&mut &mut swig_account_data[offset..offset + role.size()])
//         .map_err(|_| SwigError::SerializationError)
//         .map_err(|_| SwigError::SerializationError)?;
// }
// Ok(())
