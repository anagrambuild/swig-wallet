use borsh::BorshSerialize;
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo, msg, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};
use pinocchio_pubkey::from_str;
use swig_compact_instructions::InstructionIterator;
use swig_state::{swig_account_signer, Action, AuthorityType, SolAction, Swig, TokenAction};

use crate::{
    assertions::{check_self_owned, check_stack_height},
    error::SwigError,
    instruction::{
        accounts::{Context, SignV1Accounts},
        Authenticatable, SwigInstruction, SWIG_ACCOUNT_NAME,
    },
    util::ZeroCopy,
    AccountClassification,
};
// use swig_instructions::InstructionIterator;

pub const INSTRUCTION_SYSVAR_ACCOUNT: Pubkey =
    from_str("Sysvar1nstructions1111111111111111111111111");

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct SignV1Args {
    pub instruction: u8,
    pub role_id: u8,
    pub authority_payload_len: u16,
    pub instruction_payload_len: u16,
    pub padding: [u8; 2],
}

impl SignV1Args {
    pub fn new(role_id: u8, authority_payload_len: u16, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SignV1 as u8,
            role_id,
            authority_payload_len,
            instruction_payload_len,
            padding: [0; 2],
        }
    }
}

impl<'a> ZeroCopy<'a, SignV1Args> for SignV1Args {}

impl SignV1Args {
    const SIZE: usize = core::mem::size_of::<Self>();
}
pub struct SignV1<'a> {
    pub args: &'a SignV1Args,
    authority_payload: &'a [u8],
    instruction_payload: &'a [u8],
}

impl Authenticatable for SignV1<'_> {
    fn data_payload(&self) -> &[u8] {
        self.instruction_payload
    }
    fn authority_payload(&self) -> &[u8] {
        self.authority_payload
    }
}

impl<'a> SignV1<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (inst, rest) = data.split_at(SignV1Args::SIZE);
        let args = SignV1Args::load(inst).map_err(|e| {
            msg!("SignV1 Args Error: {:?}", e);
            ProgramError::InvalidInstructionData
        })?;

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
    check_self_owned(
        ctx.accounts.swig,
        SwigError::OwnerMismatch(SWIG_ACCOUNT_NAME),
    )?;
    let sign_v1 = SignV1::load(data).map_err(|e| {
        msg!("SignV1 Args Error: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    let id = Swig::raw_get_id(swig_account_data);
    let bump = Swig::raw_get_bump(swig_account_data);
    let (offset, mut role) = Swig::raw_get_role(swig_account_data, sign_v1.args.role_id as usize)
        .ok_or(SwigError::InvalidAuthority)?;
    let (restricted_keys, len): ([&Pubkey; 2], usize) =
        if role.authority_type == AuthorityType::Ed25519 {
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
    )
    .map_err(SwigError::from)?;
    let b = [bump];
    let signer = swig_account_signer(&id, &b);
    sign_v1.authenticate(all_accounts, &role)?;
    for ix in ix_iter {
        if let Ok(instruction) = ix {
            instruction.execute(
                all_accounts,
                ctx.accounts.swig.key(),
                &[signer.as_slice().into()],
            )?;
            msg!("Instruction executed");
        } else {
            return Err(SwigError::InstructionError(ix.err().unwrap()).into());
        }
    }
    let all = role.actions.iter().any(|action| match action {
        Action::All => true,
        _ => false,
    });
    if !all {
        for (index, account) in account_classifiers.iter().enumerate() {
            let current_account = &all_accounts[index];
            match account {
                AccountClassification::ThisSwig { lamports } => {
                    if lamports > &current_account.lamports() {
                        let amount_diff = lamports - &current_account.lamports();
                        if let Some(action) = role.actions.iter_mut().find(|action| match action {
                            Action::Sol { .. } => true,
                            _ => false,
                        }) {
                            *action = match action {
                                Action::Sol {
                                    action: SolAction::All,
                                } => Ok(Action::Sol {
                                    action: SolAction::All,
                                }),
                                Action::Sol {
                                    action: SolAction::Manage(amount),
                                } => {
                                    if *amount >= amount_diff {
                                        Ok(Action::Sol {
                                            action: SolAction::Manage(*amount - amount_diff),
                                        })
                                    } else {
                                        Err(SwigError::PermissionDenied(
                                            "Sol move exceeds the amount authorized",
                                        ))
                                    }
                                },
                                _ => Err(SwigError::PermissionDenied(
                                    "Sol cannot be moved with this role",
                                )),
                            }?;
                        } else {
                            return Err(SwigError::PermissionDenied(
                                "Sol cannot be moved with this role",
                            )
                            .into());
                        }
                    }
                },
                AccountClassification::SwigTokenAccount { balance } => {
                    // Allow account closure if the token account is empty
                    let data = unsafe { current_account.borrow_mut_data_unchecked() };
                    let mint = &data[0..32];
                    let delegate = &data[72..76];
                    let state = &data[108];
                    if delegate != &[0u8; 4] {
                        return Err(SwigError::PermissionDenied(
                            "Token account cannot be have delegate",
                        )
                        .into());
                    }
                    if *state != 1 {
                        return Err(SwigError::PermissionDenied(
                            "Token account must be initialized",
                        )
                        .into());
                    }
                    let current_token_balance = u64::from_le_bytes(
                        data[64..72]
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?,
                    );
                    if balance != &current_token_balance {
                        let amount_diff = balance - current_token_balance;
                        if let Some(action) = role.actions.iter_mut().find(|action| match action {
                            Action::Token { key, .. } if key == &mint => true,
                            Action::Tokens { .. } => true,
                            _ => false,
                        }) {
                            *action = match action {
                                Action::Token {
                                    key,
                                    action: TokenAction::All,
                                } => Ok(Action::Token {
                                    key: *key,
                                    action: TokenAction::All,
                                }),
                                Action::Token {
                                    key,
                                    action: TokenAction::Manage(amount),
                                } => {
                                    if *amount <= amount_diff {
                                        Ok(Action::Token {
                                            key: *key,
                                            action: TokenAction::Manage(*amount - amount_diff),
                                        })
                                    } else {
                                        Err(SwigError::PermissionDenied(
                                            "Token move exceeds the amount authorized",
                                        ))
                                    }
                                },
                                Action::Tokens {
                                    action: TokenAction::All,
                                } => Ok(Action::Tokens {
                                    action: TokenAction::All,
                                }),
                                Action::Tokens {
                                    action: TokenAction::Manage(amount),
                                } => {
                                    if *amount <= amount_diff {
                                        Ok(Action::Tokens {
                                            action: TokenAction::Manage(*amount - amount_diff),
                                        })
                                    } else {
                                        Err(SwigError::PermissionDenied(
                                            "Token move exceeds the amount authorized",
                                        ))
                                    }
                                },
                                _ => Err(SwigError::PermissionDenied(
                                    "Token cannot be moved with this role",
                                )),
                            }?;
                        } else {
                            return Err(SwigError::PermissionDenied(
                                "Token cannot be moved with this role",
                            )
                            .into());
                        }
                    }
                },
                _ => {},
            }
        }
        role.serialize(&mut &mut swig_account_data[offset..offset + role.size()])
            .map_err(|_| SwigError::SerializationError)
            .map_err(|_| SwigError::SerializationError)?;
    }
    Ok(())
}
