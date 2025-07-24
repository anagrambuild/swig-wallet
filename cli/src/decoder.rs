use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use solana_sdk::{instruction::CompiledInstruction, pubkey::Pubkey, transaction::Transaction};
use std::collections::HashMap;

use swig_sdk::{authority::AuthorityType, types::UpdateAuthorityData, Permission};

/// Decodes a Swig transaction and returns a JSON structure describing each instruction
pub fn decode_swig_transaction(transaction: &Transaction) -> Result<Value> {
    let mut decoded_instructions = Vec::new();

    for (index, instruction) in transaction.message.instructions.iter().enumerate() {
        let program_id = transaction.message.account_keys[instruction.program_id_index as usize];

        // Check if this is a Swig program instruction
        if is_swig_program(&program_id) {
            let decoded = decode_swig_instruction(instruction, &transaction.message.account_keys)?;
            decoded_instructions.push(json!({
                "instruction_index": index,
                "program_id": program_id.to_string(),
                "instruction_type": "swig",
                "decoded": decoded
            }));
        } else {
            // For non-Swig instructions, provide basic info
            decoded_instructions.push(json!({
                "instruction_index": index,
                "program_id": program_id.to_string(),
                "instruction_type": "other",
                "accounts": instruction.accounts.iter().map(|&idx| {
                    transaction.message.account_keys[idx as usize].to_string()
                }).collect::<Vec<_>>(),
                "data": hex::encode(&instruction.data)
            }));
        }
    }

    Ok(json!({
        "transaction": {
            "signatures": transaction.signatures.iter().map(|sig| sig.to_string()).collect::<Vec<_>>(),
            "instructions": decoded_instructions
        }
    }))
}

/// Checks if a program ID is the Swig program
fn is_swig_program(program_id: &Pubkey) -> bool {
    // Swig program ID
    program_id.to_string() == "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB"
}

/// Decodes a Swig instruction based on its discriminator
fn decode_swig_instruction(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    if instruction.data.len() < 2 {
        return Err(anyhow!("Instruction data too short"));
    }

    let discriminator = u16::from_le_bytes([instruction.data[0], instruction.data[1]]);

    match discriminator {
        0 => decode_create_v1(instruction, account_keys),
        1 => decode_add_authority_v1(instruction, account_keys),
        2 => decode_remove_authority_v1(instruction, account_keys),
        3 => decode_update_authority_v1(instruction, account_keys),
        4 => decode_sign_v1(instruction, account_keys),
        5 => decode_create_session_v1(instruction, account_keys),
        6 => decode_create_sub_account_v1(instruction, account_keys),
        7 => decode_withdraw_from_sub_account_v1(instruction, account_keys),
        9 => decode_sub_account_sign_v1(instruction, account_keys),
        10 => decode_toggle_sub_account_v1(instruction, account_keys),
        _ => Err(anyhow!(
            "Unknown instruction discriminator: {}",
            discriminator
        )),
    }
}

/// Decodes a CreateV1 instruction
fn decode_create_v1(instruction: &CompiledInstruction, account_keys: &[Pubkey]) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 48 {
        return Err(anyhow!("CreateV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let authority_type = u16::from_le_bytes([data[0], data[1]]);
    let authority_data_len = u16::from_le_bytes([data[2], data[3]]);
    let bump = data[4];
    let id = &data[6..38];

    let authority_type_str = match authority_type {
        0 => "Ed25519",
        1 => "Secp256k1",
        2 => "Secp256r1",
        3 => "Ed25519Session",
        4 => "Secp256k1Session",
        5 => "Secp256r1Session",
        _ => "Unknown",
    };

    Ok(json!({
        "instruction": "CreateV1",
        "description": "Creates a new Swig wallet",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "authority_type": authority_type_str,
            "authority_data_length": authority_data_len,
            "bump_seed": bump,
            "wallet_id": hex::encode(id),
            "authority_data": if authority_data_len > 0 && data.len() >= 38 + authority_data_len as usize {
                hex::encode(&data[38..38 + authority_data_len as usize])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes an AddAuthorityV1 instruction
fn decode_add_authority_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 24 {
        return Err(anyhow!("AddAuthorityV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let new_authority_data_len = u16::from_le_bytes([data[0], data[1]]);
    let actions_data_len = u16::from_le_bytes([data[2], data[3]]);
    let new_authority_type = u16::from_le_bytes([data[4], data[5]]);
    let num_actions = data[6];
    let acting_role_id = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let authority_type_str = match new_authority_type {
        0 => "Ed25519",
        1 => "Secp256k1",
        2 => "Secp256r1",
        3 => "Ed25519Session",
        4 => "Secp256k1Session",
        5 => "Secp256r1Session",
        _ => "Unknown",
    };

    Ok(json!({
        "instruction": "AddAuthorityV1",
        "description": "Adds a new authority to the Swig wallet",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "new_authority_type": authority_type_str,
            "new_authority_data_length": new_authority_data_len,
            "actions_data_length": actions_data_len,
            "num_actions": num_actions,
            "acting_role_id": acting_role_id,
            "new_authority_data": if new_authority_data_len > 0 && data.len() >= 12 + new_authority_data_len as usize {
                hex::encode(&data[12..12 + new_authority_data_len as usize])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes a RemoveAuthorityV1 instruction
fn decode_remove_authority_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    Ok(json!({
        "instruction": "RemoveAuthorityV1",
        "description": "Removes an authority from the Swig wallet",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "authority_to_remove": hex::encode(&instruction.data[2..])
        }
    }))
}

/// Decodes an UpdateAuthorityV1 instruction
fn decode_update_authority_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 16 {
        return Err(anyhow!("UpdateAuthorityV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let acting_role_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let authority_to_update_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let operation_data_len = u16::from_le_bytes([data[8], data[9]]);

    let operation = if data.len() > 12 {
        match data[12] {
            0 => "ReplaceAll",
            1 => "AddActions",
            2 => "RemoveActionsByType",
            3 => "RemoveActionsByIndex",
            _ => "Unknown",
        }
    } else {
        "Unknown"
    };

    Ok(json!({
        "instruction": "UpdateAuthorityV1",
        "description": "Updates an existing authority in the Swig wallet",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "acting_role_id": acting_role_id,
            "authority_to_update_id": authority_to_update_id,
            "operation": operation,
            "operation_data_length": operation_data_len,
            "operation_data": if operation_data_len > 0 && data.len() >= 12 + operation_data_len as usize {
                hex::encode(&data[12..12 + operation_data_len as usize])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes a SignV1 instruction
fn decode_sign_v1(instruction: &CompiledInstruction, account_keys: &[Pubkey]) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 10 {
        return Err(anyhow!("SignV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let instruction_payload_len = u16::from_le_bytes([data[0], data[1]]);
    let role_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

    let instruction_payload = if instruction_payload_len > 0
        && data.len() >= 6 + instruction_payload_len as usize
    {
        decode_compact_instructions(&data[6..6 + instruction_payload_len as usize], account_keys)?
    } else {
        json!([])
    };

    Ok(json!({
        "instruction": "SignV1",
        "description": "Signs and executes a transaction using the wallet's authority",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "role_id": role_id,
            "instruction_payload_length": instruction_payload_len,
            "instruction_payload": instruction_payload,
            "authority_payload": if data.len() > 6 + instruction_payload_len as usize {
                hex::encode(&data[6 + instruction_payload_len as usize..])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes a CreateSessionV1 instruction
fn decode_create_session_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 52 {
        return Err(anyhow!("CreateSessionV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let role_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let session_duration = u64::from_le_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);
    let session_key = &data[12..44];

    Ok(json!({
        "instruction": "CreateSessionV1",
        "description": "Creates a new session for temporary authority",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "role_id": role_id,
            "session_duration_slots": session_duration,
            "session_key": hex::encode(session_key),
            "authority_payload": if data.len() > 44 {
                hex::encode(&data[44..])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes a CreateSubAccountV1 instruction
fn decode_create_sub_account_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 12 {
        return Err(anyhow!("CreateSubAccountV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let role_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let sub_account_bump = data[4];

    Ok(json!({
        "instruction": "CreateSubAccountV1",
        "description": "Creates a new sub-account under the wallet",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "sub_account": accounts.get(2).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(3).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "role_id": role_id,
            "sub_account_bump": sub_account_bump,
            "authority_payload": if data.len() > 5 {
                hex::encode(&data[5..])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes a WithdrawFromSubAccountV1 instruction
fn decode_withdraw_from_sub_account_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    Ok(json!({
        "instruction": "WithdrawFromSubAccountV1",
        "description": "Withdraws funds from a sub-account to the main wallet",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "sub_account": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "withdrawal_data": hex::encode(&instruction.data[2..])
        }
    }))
}

/// Decodes a SubAccountSignV1 instruction
fn decode_sub_account_sign_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    if instruction.data.len() < 10 {
        return Err(anyhow!("SubAccountSignV1 instruction data too short"));
    }

    let data = &instruction.data[2..]; // Skip discriminator
    let instruction_payload_len = u16::from_le_bytes([data[0], data[1]]);
    let role_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

    let instruction_payload = if instruction_payload_len > 0
        && data.len() >= 6 + instruction_payload_len as usize
    {
        decode_compact_instructions(&data[6..6 + instruction_payload_len as usize], account_keys)?
    } else {
        json!([])
    };

    Ok(json!({
        "instruction": "SubAccountSignV1",
        "description": "Signs and executes a transaction from a sub-account",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "sub_account": accounts.get(2).unwrap_or(&"unknown".to_string()),
            "system_program": accounts.get(3).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "role_id": role_id,
            "instruction_payload_length": instruction_payload_len,
            "instruction_payload": instruction_payload,
            "authority_payload": if data.len() > 6 + instruction_payload_len as usize {
                hex::encode(&data[6 + instruction_payload_len as usize..])
            } else {
                "".to_string()
            }
        }
    }))
}

/// Decodes a ToggleSubAccountV1 instruction
fn decode_toggle_sub_account_v1(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<Value> {
    let accounts = get_account_names(instruction, account_keys);

    Ok(json!({
        "instruction": "ToggleSubAccountV1",
        "description": "Toggles the enabled state of a sub-account",
        "accounts": {
            "swig_wallet": accounts.get(0).unwrap_or(&"unknown".to_string()),
            "payer": accounts.get(1).unwrap_or(&"unknown".to_string()),
            "sub_account": accounts.get(2).unwrap_or(&"unknown".to_string()),
        },
        "data": {
            "toggle_data": hex::encode(&instruction.data[2..])
        }
    }))
}

/// Decodes compact instructions format
fn decode_compact_instructions(data: &[u8], account_keys: &[Pubkey]) -> Result<Value> {
    if data.is_empty() {
        return Ok(json!([]));
    }

    todo!()
}

/// Gets account names for an instruction
fn get_account_names(instruction: &CompiledInstruction, account_keys: &[Pubkey]) -> Vec<String> {
    instruction
        .accounts
        .iter()
        .map(|&idx| {
            if (idx as usize) < account_keys.len() {
                account_keys[idx as usize].to_string()
            } else {
                "unknown".to_string()
            }
        })
        .collect()
}
