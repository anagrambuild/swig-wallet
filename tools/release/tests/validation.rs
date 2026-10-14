use anyhow::Result;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::{
    account::Account,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::TransactionError,
};
use solana_sdk_ids::bpf_loader_upgradeable;
use squads_multisig::{
    anchor_lang::AccountSerialize,
    pda::{get_multisig_pda, get_vault_pda},
    state::{Member, Multisig, Permission, Permissions},
};
use swig_release::{
    accounts::{validate_buffer, validate_capacity, validate_multisig, validate_program},
    config::{parse_proposer, ReleaseConfig},
    proposal::{confirmation_complete, require_next_index, validate_release_identity},
};

fn buffer_account(authority: Option<Pubkey>, payload: &[u8]) -> Result<Account> {
    let mut data = bincode::serialize(&UpgradeableLoaderState::Buffer {
        authority_address: authority,
    })?;
    data.resize(UpgradeableLoaderState::size_of_buffer_metadata(), 0);
    data.extend_from_slice(payload);
    Ok(Account {
        lamports: 1_000_000_000,
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
    })
}

#[test]
fn buffer_requires_exact_size_and_contents() -> Result<()> {
    let authority = Pubkey::new_unique();
    let binary = b"\x7fELFpayload";
    validate_buffer(&buffer_account(Some(authority), binary)?, binary, authority)?;
    for payload in [
        &binary[..binary.len() - 1],
        b"\x7fELFpayload-padding".as_slice(),
    ] {
        let error = validate_buffer(
            &buffer_account(Some(authority), payload)?,
            binary,
            authority,
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("Expected size rejection"))?;
        assert_eq!(
            error.to_string(),
            "Buffer payload size does not match the binary"
        );
    }
    let error = validate_buffer(
        &buffer_account(Some(authority), b"\x7fELFpayloae")?,
        binary,
        authority,
    )
    .err()
    .ok_or_else(|| anyhow::anyhow!("Expected content rejection"))?;
    assert_eq!(
        error.to_string(),
        "Uploaded buffer contents do not match the built binary"
    );
    Ok(())
}

#[test]
fn buffer_rejects_wrong_or_missing_authority() -> Result<()> {
    let expected = Pubkey::new_unique();
    for authority in [None, Some(Pubkey::new_unique())] {
        let error = validate_buffer(&buffer_account(authority, b"binary")?, b"binary", expected)
            .err()
            .ok_or_else(|| anyhow::anyhow!("Expected authority rejection"))?;
        assert_eq!(
            error.to_string(),
            "Buffer authority does not match the expected signer"
        );
    }
    Ok(())
}

#[test]
fn buffer_rejects_owner_executable_and_truncation() -> Result<()> {
    let authority = Pubkey::new_unique();
    let mut account = buffer_account(Some(authority), b"binary")?;
    account.owner = Pubkey::new_unique();
    assert_eq!(
        validate_buffer(&account, b"binary", authority)
            .err()
            .map(|error| error.to_string()),
        Some("Buffer has an incorrect owner or executable flag".into())
    );
    account.owner = bpf_loader_upgradeable::id();
    account.executable = true;
    assert!(validate_buffer(&account, b"binary", authority).is_err());
    account.executable = false;
    account.data.truncate(36);
    assert_eq!(
        validate_buffer(&account, b"binary", authority)
            .err()
            .map(|error| error.to_string()),
        Some("Truncated Buffer account".into())
    );
    Ok(())
}

#[test]
fn capacity_accepts_exact_fit_and_reports_shortfall() -> Result<()> {
    validate_capacity(100, 100)?;
    validate_capacity(100, 101)?;
    assert_eq!(
        validate_capacity(101, 100)
            .err()
            .map(|error| error.to_string()),
        Some(
            "Program capacity is 100 bytes; binary needs 101 bytes (1 additional bytes required)"
                .into()
        )
    );
    Ok(())
}

#[test]
fn program_capacity_excludes_metadata_and_binds_authority() -> Result<()> {
    let key = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let program_data_key =
        Pubkey::find_program_address(&[key.as_ref()], &bpf_loader_upgradeable::id()).0;
    let mut program = Account {
        lamports: 1,
        owner: bpf_loader_upgradeable::id(),
        executable: true,
        rent_epoch: 0,
        data: bincode::serialize(&UpgradeableLoaderState::Program {
            programdata_address: program_data_key,
        })?,
    };
    let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 1,
        upgrade_authority_address: Some(vault),
    })?;
    data.resize(UpgradeableLoaderState::size_of_programdata(100), 0);
    let mut program_data = Account {
        lamports: 1,
        owner: bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
        data,
    };
    assert_eq!(validate_program(key, &program, &program_data, vault)?, 100);
    assert_eq!(
        validate_program(key, &program, &program_data, Pubkey::new_unique())
            .err()
            .map(|error| error.to_string()),
        Some("Program upgrade authority must be the configured Squads vault".into())
    );
    program.data = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: Pubkey::new_unique(),
    })?;
    assert_eq!(
        validate_program(key, &program, &program_data, vault)
            .err()
            .map(|error| error.to_string()),
        Some("Program account does not reference its canonical ProgramData address".into())
    );
    program.data = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: program_data_key,
    })?;
    program_data.data.truncate(44);
    assert_eq!(
        validate_program(key, &program, &program_data, vault)
            .err()
            .map(|error| error.to_string()),
        Some("Truncated ProgramData account".into())
    );
    Ok(())
}

#[test]
fn multisig_requires_configured_owner_pda_and_initiate_permission() -> Result<()> {
    let squads_program = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (address, bump) = get_multisig_pda(&create_key, Some(&squads_program));
    let proposer = Pubkey::new_unique();
    let voter = Pubkey::new_unique();
    let config = ReleaseConfig {
        rpc_url: "https://example.invalid".into(),
        squads_program,
        multisig: address,
        vault_index: 3,
        program: Pubkey::new_unique(),
    };
    let mut members = vec![
        Member {
            key: proposer,
            permissions: Permissions::from_vec(&[Permission::Initiate]),
        },
        Member {
            key: voter,
            permissions: Permissions::from_vec(&[Permission::Vote, Permission::Execute]),
        },
    ];
    members.sort_by_key(|member| member.key);
    let multisig = Multisig {
        create_key,
        config_authority: Pubkey::default(),
        threshold: 1,
        time_lock: 0,
        transaction_index: 4,
        stale_transaction_index: 0,
        rent_collector: None,
        bump,
        members,
    };
    let mut bytes = Vec::new();
    multisig.try_serialize(&mut bytes)?;
    let mut account = Account {
        lamports: 1,
        owner: squads_program,
        executable: false,
        rent_epoch: 0,
        data: bytes,
    };
    let decoded = validate_multisig(&config, &account, proposer)?;
    assert_eq!(decoded.transaction_index, 4);
    assert_eq!(
        validate_multisig(&config, &account, voter)
            .err()
            .map(|error| error.to_string()),
        Some("PROPOSER_KEYPAIR must have Squads Initiate permission".into())
    );
    account.owner = Pubkey::new_unique();
    assert_eq!(
        validate_multisig(&config, &account, proposer)
            .err()
            .map(|error| error.to_string()),
        Some("Multisig has an incorrect owner or executable flag".into())
    );
    account.owner = squads_program;
    let mut wrong_config = config;
    wrong_config.multisig = Pubkey::new_unique();
    assert_eq!(
        validate_multisig(&wrong_config, &account, proposer)
            .err()
            .map(|error| error.to_string()),
        Some("Multisig PDA does not match its create key".into())
    );
    assert_ne!(
        get_vault_pda(&address, 3, Some(&squads_program)).0,
        get_vault_pda(&address, 0, Some(&squads_program)).0
    );
    Ok(())
}

#[test]
fn secret_errors_never_echo_key_material() -> Result<()> {
    let key = Keypair::new();
    let json = serde_json::to_string(&key.to_bytes().to_vec())?;
    assert_eq!(parse_proposer(&json)?.pubkey(), key.pubkey());
    let sentinel = "secret-should-not-appear";
    let error = parse_proposer(sentinel)
        .err()
        .ok_or_else(|| anyhow::anyhow!("Expected invalid key"))?;
    assert!(!format!("{error:#}").contains(sentinel));
    assert!(parse_proposer("[1,2,3]").is_err());
    Ok(())
}

#[test]
fn transaction_index_is_fixed_and_checked() -> Result<()> {
    require_next_index(5, 6)?;
    assert!(require_next_index(5, 5).is_err());
    assert!(require_next_index(5, 7).is_err());
    assert!(require_next_index(u64::MAX, 0).is_err());
    Ok(())
}

#[test]
fn confirmation_distinguishes_unknown_success_and_failure() -> Result<()> {
    assert!(!confirmation_complete(None)?);
    assert!(confirmation_complete(Some(Ok(())))?);
    assert!(confirmation_complete(Some(Err(TransactionError::AccountNotFound))).is_err());
    Ok(())
}

#[test]
fn release_identity_rejects_ambiguous_commits_and_tags() -> Result<()> {
    let sha = "a".repeat(40);
    validate_release_identity(&sha, "upgrade-12-abcdef012345")?;
    for commit in ["main", "abcdef", "not-a-sha"] {
        assert!(validate_release_identity(commit, "upgrade-12").is_err());
    }
    for tag in ["", "../main", "release;command", "release\nmessage"] {
        assert!(validate_release_identity(&sha, tag).is_err());
    }
    Ok(())
}
