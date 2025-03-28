use borsh::BorshSerialize;
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo, msg, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};
use pinocchio_pubkey::from_str;
use swig_compact_instructions::InstructionIterator;
use swig_state::{
    swig_account_signer, swig_pim_account_signer, Action, AuthorityType, PluginBytecodeAccount,
    SolAction, Swig, TokenAction, VMInstruction,
};

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

pub const SYSTEM_PROGRAM_ID: Pubkey = from_str("11111111111111111111111111111111");

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct SignV1Args {
    pub instruction: u8,
    pub role_id: u8,
    pub authority_payload_len: u16,
    pub instruction_payload_len: u16,
    pub plugin_target_indices_len: u8,
    pub padding: u8,
}

impl SignV1Args {
    pub fn new(
        role_id: u8,
        authority_payload_len: u16,
        instruction_payload_len: u16,
        plugin_target_indices_len: u8,
    ) -> Self {
        Self {
            instruction: SwigInstruction::SignV1 as u8,
            role_id,
            authority_payload_len,
            instruction_payload_len,
            plugin_target_indices_len,
            padding: 0,
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
    plugin_target_indices: &'a [u8],
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

        let (authority_payload, rest) = rest.split_at(args.authority_payload_len as usize);

        let (plugin_target_indices, instruction_payload) =
            rest.split_at(args.plugin_target_indices_len as usize);

        Ok(Self {
            args,
            authority_payload,
            plugin_target_indices,
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

    // Authenticate the transaction first
    sign_v1.authenticate(all_accounts, &role)?;

    // msg!(
    //     "ctx.remaining_accounts.is_empty(): {:?}",
    //     ctx.remaining_accounts.is_empty()
    // );
    // msg!(
    //     "sign_v1.args.plugin_target_indices_len: {:?}",
    //     sign_v1.args.plugin_target_indices_len
    // );

    // Skip plugin execution if no remaining accounts or no plugin target indices
    if !ctx.remaining_accounts.is_empty() && sign_v1.args.plugin_target_indices_len > 0 {
        // Inline fast path for simple cases
        if sign_v1.args.plugin_target_indices_len == 1 {
            // Get the single target index
            let idx = sign_v1.plugin_target_indices[0] as usize;

            // msg!("idx: {:?}", idx);
            // msg!("all_accounts.len(): {:?}", all_accounts.len());

            // Skip invalid indices
            if idx < all_accounts.len() {
                let account = &all_accounts[idx];
                let owner = account.owner();

                // Skip system program and our own program
                // msg!(
                //     "owner != &SYSTEM_PROGRAM_ID && owner != &crate::ID: {:?}",
                //     owner != &SYSTEM_PROGRAM_ID && owner != &crate::ID
                // );
                // msg!(
                //     "owner != &SYSTEM_PROGRAM_ID: {:?}",
                //     owner != &SYSTEM_PROGRAM_ID
                // );
                // msg!("owner != &crate::ID: {:?}", owner != &crate::ID);
                if owner != &crate::ID {
                    // Try to find matching plugin
                    for ra in ctx.remaining_accounts.iter() {
                        // Quick ownership and size check
                        // msg!("ra.owner() == &crate::ID: {:?}", ra.owner() == &crate::ID);
                        // msg!(
                        //     "ra.data_len() >= std::mem::size_of::<PluginBytecodeAccount>():
                        // {:?}",     ra.data_len() >=
                        // std::mem::size_of::<PluginBytecodeAccount>() );
                        if ra.owner() == &crate::ID
                            && ra.data_len() >= std::mem::size_of::<PluginBytecodeAccount>()
                        {
                            // Get plugin data
                            let data = unsafe { ra.borrow_data_unchecked() };
                            let plugin = bytemuck::from_bytes::<PluginBytecodeAccount>(&data);

                            // msg!(
                            //     "&plugin.target_program == owner: {:?}",
                            //     &plugin.target_program == owner
                            // );
                            // Check program match
                            if &plugin.target_program == owner {
                                // Execute the plugin - pass all indices
                                let _ = execute_plugin_bytecode(
                                    plugin,
                                    account,
                                    idx,
                                    sign_v1.plugin_target_indices,
                                    all_accounts,
                                )?;
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            // Multi-index case
            for &idx in sign_v1.plugin_target_indices.iter() {
                let idx = idx as usize;
                if idx >= all_accounts.len() {
                    continue;
                }

                let account = &all_accounts[idx];
                let owner = account.owner();

                if owner == &crate::ID {
                    continue;
                }

                for ra in ctx.remaining_accounts.iter() {
                    if ra.owner() != &crate::ID
                        || ra.data_len() < std::mem::size_of::<PluginBytecodeAccount>()
                    {
                        continue;
                    }

                    let data = unsafe { ra.borrow_data_unchecked() };
                    let plugin = bytemuck::from_bytes::<PluginBytecodeAccount>(&data);

                    if &plugin.target_program != owner {
                        continue;
                    }

                    let (pda, _) = pinocchio::pubkey::find_program_address(
                        &[b"swig-pim", owner.as_ref()],
                        &crate::ID,
                    );

                    if ra.key() == &pda {
                        // Pass all plugin target indices, not just a single one
                        let _ = execute_plugin_bytecode(
                            plugin,
                            account,
                            idx,
                            sign_v1.plugin_target_indices,
                            all_accounts,
                        )?;
                        break;
                    }
                }
            }
        }
    }

    // Continue with the original sign_v1 flow after plugin execution
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v1.instruction_payload,
        ctx.accounts.swig.key(),
        &restricted_keys[0..len],
    )
    .map_err(SwigError::from)?;
    let b = [bump];
    let signer = swig_account_signer(&id, &b);

    // Execute the instructions
    for ix in ix_iter {
        if let Ok(instruction) = ix {
            instruction.execute(
                all_accounts,
                ctx.accounts.swig.key(),
                &[signer.as_slice().into()],
            )?;
        } else {
            return Err(SwigError::InstructionError(ix.err().unwrap()).into());
        }
    }

    // Continue with the existing permission checks
    let all = role
        .actions
        .iter()
        .any(|action| matches!(action, Action::All));
    if !all {
        for (index, account) in account_classifiers.iter().enumerate() {
            let current_account = &all_accounts[index];
            match account {
                AccountClassification::ThisSwig { lamports } => {
                    if lamports > &current_account.lamports() {
                        let amount_diff = lamports - current_account.lamports();
                        if let Some(action) = role
                            .actions
                            .iter_mut()
                            .find(|action| matches!(action, Action::Sol { .. }))
                        {
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
                    if delegate != [0u8; 4] {
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
            .map_err(|_| SwigError::SerializationError)?;
    }
    Ok(())
}

// Extract the plugin execution logic into a separate function to improve
// readability and enable inlining optimizations
#[inline(always)]
fn execute_plugin_bytecode(
    plugin_bytecode_account: &PluginBytecodeAccount,
    primary_account: &AccountInfo,
    _index: usize,
    account_indices: &[u8],
    all_accounts: &[AccountInfo],
) -> Result<i64, ProgramError> {
    // Initialize stack with fixed capacity
    let mut stack = Vec::with_capacity(8);
    let mut pc = 0;
    let instr_len = plugin_bytecode_account.instructions_len as usize;

    // msg!(
    //     "Executing plugin for primary_account: {:?}",
    //     primary_account.key()
    // );
    // msg!("Account indices for plugin: {:?}", account_indices);
    // for (i, &idx) in account_indices.iter().enumerate() {
    //     if (idx as usize) < all_accounts.len() {
    //         msg!(
    //             "Account at index {}: {:?}",
    //             idx,
    //             all_accounts[idx as usize].key()
    //         );
    //     }
    // }

    // Fast path VM implementation
    while pc < instr_len {
        let instr = plugin_bytecode_account.instructions[pc];
        match instr {
            VMInstruction::PushValue { value } => {
                stack.push(value);
                pc += 1;
            },
            VMInstruction::LoadField {
                account_index,
                field_offset,
                ..
            } => {
                // Use account_index to determine which account to read from
                let account_data = if account_index == 0 {
                    // Use the primary account (typically the stake account)
                    // msg!("Loading from primary account at offset {}", field_offset);
                    primary_account.try_borrow_data()?
                } else if account_index == 0xFF {
                    // Special case: Load the account's own pubkey as data (used for key
                    // comparisons)
                    // msg!("Loading pubkey bytes from primary account");
                    let pubkey_bytes = primary_account.key(); // Already a &[u8; 32]
                    let bytes = &pubkey_bytes[field_offset as usize..field_offset as usize + 8];
                    // msg!("Loaded pubkey bytes: {:?}", bytes);

                    // Print as hex values
                    let mut hex_str = String::new();
                    for b in bytes.iter() {
                        hex_str.push_str(&format!("{:02x} ", b));
                    }
                    // msg!("Pubkey bytes as hex: {}", hex_str);

                    let value = i64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    // msg!("Pushing value into stack: {}", value);
                    stack.push(value);
                    pc += 1;
                    continue;
                } else if account_index as usize <= account_indices.len() {
                    // Get the actual transaction account using the provided index
                    let idx = account_indices[account_index as usize - 1] as usize;

                    // Debug the account index resolution
                    // msg!(
                    //     "Resolving account_index {} to transaction account at index {}",
                    //     account_index,
                    //     idx
                    // );
                    if idx >= all_accounts.len() {
                        return Err(ProgramError::Custom(400)); // InvalidAccountIndex
                    }

                    // Check if we should load the account's pubkey instead of its data
                    if field_offset >= 0xFF00 {
                        // Load from account's public key bytes
                        let pubkey_bytes = all_accounts[idx].key(); // Already a &[u8; 32]
                        let offset = (field_offset - 0xFF00) as usize;
                        if offset + 8 > 32 {
                            // pubkey is 32 bytes
                            return Err(ProgramError::Custom(401)); // InvalidFieldOffset
                        }

                        let bytes = &pubkey_bytes[offset..offset + 8];
                        // msg!(
                        //     "Loading pubkey bytes from account at index {}, offset {}: {:?}",
                        //     idx,
                        //     offset,
                        //     bytes
                        // );

                        // Print as hex values
                        let mut hex_str = String::new();
                        for b in bytes.iter() {
                            hex_str.push_str(&format!("{:02x} ", b));
                        }
                        // msg!("Pubkey bytes as hex: {}", hex_str);

                        let value = i64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        // msg!("Pushing value into stack: {}", value);
                        stack.push(value);
                        pc += 1;
                        continue;
                    }

                    // Print the actual account key we're accessing
                    // msg!(
                    //     "Loading from account {} ({}), key: {:?}",
                    //     account_index,
                    //     idx,
                    //     all_accounts[idx].key()
                    // );
                    all_accounts[idx].try_borrow_data()?
                } else {
                    // msg!(
                    //     "invalid account index: {:?} : {:?}",
                    //     account_index,
                    //     account_indices.len()
                    // );
                    return Err(ProgramError::Custom(400)); // InvalidAccountIndex
                };

                let offset = field_offset as usize;
                if offset + 8 > account_data.len() {
                    return Err(ProgramError::Custom(401)); // InvalidFieldOffset
                }

                let bytes = &account_data[offset..offset + 8];
                // msg!("Loaded bytes: {:?}", bytes);

                // Print as decimal values for easier comparison
                let mut hex_str = String::new();
                for b in bytes.iter() {
                    hex_str.push_str(&format!("{:02x} ", b));
                }
                // msg!("Bytes as hex: {}", hex_str);

                let value = i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                // msg!("Pushing value into stack: {}", value);
                stack.push(value);
                pc += 1;
            },
            VMInstruction::Add => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402)); // StackUnderflow
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a + b);
                pc += 1;
            },
            VMInstruction::Subtract => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a - b);
                pc += 1;
            },
            VMInstruction::Multiply => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a * b);
                pc += 1;
            },
            VMInstruction::Divide => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                if b == 0 {
                    return Err(ProgramError::Custom(403)); // DivisionByZero
                }
                let a = stack.pop().unwrap();
                stack.push(a / b);
                pc += 1;
            },
            VMInstruction::Equal => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                // msg!("a: {:?}", a);
                // msg!("b: {:?}", b);
                // msg!("a == b: {:?}", a == b);
                stack.push(if a == b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::GreaterThan => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a > b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::LessThan => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a < b { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::And => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 && b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Or => {
                if stack.len() < 2 {
                    return Err(ProgramError::Custom(402));
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(if a != 0 || b != 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::Not => {
                if stack.is_empty() {
                    return Err(ProgramError::Custom(402));
                }
                let a = stack.pop().unwrap();
                stack.push(if a == 0 { 1 } else { 0 });
                pc += 1;
            },
            VMInstruction::JumpIf { offset, .. } => {
                if stack.is_empty() {
                    return Err(ProgramError::Custom(402));
                }
                let condition = stack.pop().unwrap();
                if condition != 0 {
                    pc = pc.wrapping_add(offset as usize);
                    if pc >= instr_len {
                        return Err(ProgramError::Custom(404)); // InvalidJump
                    }
                } else {
                    pc += 1;
                }
            },
            VMInstruction::Return => {
                if stack.is_empty() {
                    return Err(ProgramError::Custom(402));
                }
                // Exit the loop
                break;
            },
        }

        // Check stack overflow (32 is a reasonable limit for a bytecode VM)
        if stack.len() > 32 {
            return Err(ProgramError::Custom(405)); // StackOverflow
        }
    }

    // We run until stack has 1 value which is the result
    // result of 1 means validation passes, 0 means validation fails
    let result = stack.last().copied().unwrap_or(0);
    msg!("result: {}", result);

    // If the plugin validation fails (result is 0), return an error
    if result == 0 {
        msg!("Plugin validation failed: authorities do not match");
        return Err(ProgramError::Custom(406)); // ValidationFailed
    }

    // Return the result for success
    Ok(result)
}
