use serde_json::json;
use solana_account_decoder_client_types::{UiAccount, UiAccountData, UiAccountEncoding};
use solana_client::rpc_response::RpcKeyedAccount;

use super::*;
use crate::types::{TokenBalance, TokenProgram};

#[test_log::test]
fn test_parse_spl_token_account() {
    let account_pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
    let mint_pubkey = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // USDC

    let parsed_data = json!({
        "info": {
            "mint": mint_pubkey,
            "owner": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            "tokenAmount": {
                "amount": "1000000",
                "decimals": 6,
                "uiAmount": 1.0,
                "uiAmountString": "1.0"
            }
        },
        "type": "account"
    });

    let rpc_account = RpcKeyedAccount {
        pubkey: account_pubkey.clone(),
        account: UiAccount {
            lamports: 2039280,
            owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            data: UiAccountData::Json(solana_account_decoder_client_types::ParsedAccount {
                program: "spl-token".to_string(),
                parsed: parsed_data,
                space: 165,
            }),
            executable: false,
            rent_epoch: 0,
            space: Some(165),
        },
    };

    let result = crate::wallet::parse_token_account_rpc(&rpc_account, TokenProgram::SplToken);

    assert!(result.is_ok());
    let balance = result.unwrap();
    assert!(balance.is_some());

    let balance = balance.unwrap();
    assert_eq!(balance.mint.to_string(), mint_pubkey);
    assert_eq!(balance.balance, 1000000);
    assert_eq!(balance.decimals, 6);
    assert_eq!(balance.ui_amount, 1.0);
    assert!(matches!(balance.program, TokenProgram::SplToken));
}

#[test_log::test]
fn test_parse_token2022_account() {
    let account_pubkey = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string();
    let mint_pubkey = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"; // USDC on Token-2022

    let parsed_data = json!({
        "info": {
            "mint": mint_pubkey,
            "owner": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            "tokenAmount": {
                "amount": "500000000",
                "decimals": 9,
                "uiAmount": 0.5,
                "uiAmountString": "0.5"
            }
        },
        "type": "account"
    });

    let rpc_account = RpcKeyedAccount {
        pubkey: account_pubkey.clone(),
        account: UiAccount {
            lamports: 2039280,
            owner: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string(),
            data: UiAccountData::Json(solana_account_decoder_client_types::ParsedAccount {
                program: "spl-token-2022".to_string(),
                parsed: parsed_data,
                space: 165,
            }),
            executable: false,
            rent_epoch: 0,
            space: Some(165),
        },
    };

    let result = crate::wallet::parse_token_account_rpc(&rpc_account, TokenProgram::Token2022);

    assert!(result.is_ok());
    let balance = result.unwrap();
    assert!(balance.is_some());

    let balance = balance.unwrap();
    assert_eq!(balance.mint.to_string(), mint_pubkey);
    assert_eq!(balance.balance, 500000000);
    assert_eq!(balance.decimals, 9);
    assert_eq!(balance.ui_amount, 0.5);
    assert!(matches!(balance.program, TokenProgram::Token2022));
}

#[test_log::test]
fn test_parse_zero_balance_account() {
    let parsed_data = json!({
        "info": {
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "owner": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            "tokenAmount": {
                "amount": "0",
                "decimals": 6,
                "uiAmount": 0.0,
                "uiAmountString": "0"
            }
        },
        "type": "account"
    });

    let rpc_account = RpcKeyedAccount {
        pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        account: UiAccount {
            lamports: 2039280,
            owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            data: UiAccountData::Json(solana_account_decoder_client_types::ParsedAccount {
                program: "spl-token".to_string(),
                parsed: parsed_data,
                space: 165,
            }),
            executable: false,
            rent_epoch: 0,
            space: Some(165),
        },
    };

    let result = crate::wallet::parse_token_account_rpc(&rpc_account, TokenProgram::SplToken);

    assert!(result.is_ok());
    let balance = result.unwrap();
    assert!(balance.is_some());

    let balance = balance.unwrap();
    assert_eq!(balance.balance, 0);
    assert_eq!(balance.ui_amount, 0.0);
}

#[test_log::test]
fn test_parse_non_json_account() {
    let rpc_account = RpcKeyedAccount {
        pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        account: UiAccount {
            lamports: 2039280,
            owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            data: UiAccountData::Binary("some-base64-data".to_string(), UiAccountEncoding::Base64),
            executable: false,
            rent_epoch: 0,
            space: Some(165),
        },
    };

    let result = crate::wallet::parse_token_account_rpc(&rpc_account, TokenProgram::SplToken);

    assert!(result.is_ok());
    let balance = result.unwrap();
    assert!(balance.is_none());
}

#[test_log::test]
fn test_parse_account_missing_info() {
    let parsed_data = json!({
        "type": "account"

    });

    let rpc_account = RpcKeyedAccount {
        pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        account: UiAccount {
            lamports: 2039280,
            owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            data: UiAccountData::Json(solana_account_decoder_client_types::ParsedAccount {
                program: "spl-token".to_string(),
                parsed: parsed_data,
                space: 165,
            }),
            executable: false,
            rent_epoch: 0,
            space: Some(165),
        },
    };

    let result = crate::wallet::parse_token_account_rpc(&rpc_account, TokenProgram::SplToken);

    assert!(result.is_ok());
    let balance = result.unwrap();
    assert!(balance.is_none()); // Should return None when info is missing
}
