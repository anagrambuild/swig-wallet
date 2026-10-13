//! Owns the offline validator, temporary keys, deployment fixtures and CLI subprocesses.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_sdk_ids::system_program;
use squads_multisig::{
    anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas},
    pda::{
        get_multisig_pda, get_program_config_pda, get_proposal_pda, get_transaction_pda,
        get_vault_pda,
    },
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_api::request::RpcRequest,
    squads_multisig_program::{self as squads, Member, Permission, Permissions},
};
use std::{
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    time::Duration,
};
use swig_release::config::ReleaseConfig;

pub(super) const SOURCE_COMMIT: &str = "34f010f77f27052e895100c808cf8769a15f97a5";

struct OwnedProcess(Child);

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) struct Fixture {
    _surfpool: OwnedProcess,
    pub(super) rpc: RpcClient,
    pub(super) config: ReleaseConfig,
    pub(super) proposer: Keypair,
    pub(super) voter: Keypair,
    pub(super) binary: Vec<u8>,
    pub(super) binary_path: PathBuf,
    pub(super) directory: tempfile::TempDir,
}

impl Fixture {
    pub(super) async fn start() -> Result<Self> {
        let binary_path = fs::canonicalize(
            env::var("SWIG_TEST_BINARY").context("Set SWIG_TEST_BINARY to the built Swig .so")?,
        )?;
        let squads_path = env::var("SQUADS_TEST_BINARY")
            .context("Set SQUADS_TEST_BINARY to the pinned Squads .so")?;
        let binary = fs::read(&binary_path)?;
        let squads_binary = fs::read(squads_path)?;
        let directory = tempfile::tempdir()?;
        let rpc_listener = TcpListener::bind("127.0.0.1:0")?;
        let ws_listener = TcpListener::bind("127.0.0.1:0")?;
        let rpc_port = rpc_listener.local_addr()?.port();
        let ws_port = ws_listener.local_addr()?.port();
        drop((rpc_listener, ws_listener));
        let log = fs::File::create(directory.path().join("surfpool.log"))?;
        let mut surfpool = OwnedProcess(
            Command::new("surfpool")
                .args([
                    "start",
                    "--offline",
                    "--no-deploy",
                    "--no-tui",
                    "--no-studio",
                    "--airdrop-amount",
                    "0",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &rpc_port.to_string(),
                    "--ws-port",
                    &ws_port.to_string(),
                ])
                .current_dir(directory.path())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let rpc_url = format!("http://127.0.0.1:{rpc_port}");
        let rpc = RpcClient::new_with_timeout_and_commitment(
            rpc_url.clone(),
            Duration::from_secs(5),
            CommitmentConfig::confirmed(),
        );
        let mut healthy = false;
        for _ in 0..100 {
            ensure!(
                surfpool.0.try_wait()?.is_none(),
                "Surfpool exited: {}",
                fs::read_to_string(directory.path().join("surfpool.log"))?
            );
            if rpc.get_health().await.is_ok() {
                healthy = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(healthy, "Surfpool did not become healthy");
        let proposer = Keypair::new();
        let voter = Keypair::new();
        let seed = Keypair::new();
        let squads_program = squads::id();
        let multisig = get_multisig_pda(&seed.pubkey(), Some(&squads_program)).0;
        let program = Keypair::new().pubkey();
        // A nonzero index also catches accidental reliance on vault 0.
        let vault_index = 3;
        let vault = get_vault_pda(&multisig, vault_index, Some(&squads_program)).0;
        let config = ReleaseConfig {
            rpc_url,
            squads_program,
            multisig,
            vault_index,
            program,
        };
        let fixture = Self {
            rpc,
            config,
            proposer,
            voter,
            binary,
            binary_path,
            directory,
            _surfpool: surfpool,
        };
        for signer in [&fixture.proposer, &fixture.voter] {
            fixture
                .rpc
                .request_airdrop(&signer.pubkey(), 100_000_000_000)
                .await?;
        }
        // Only bootstrap program deployment/global config uses cheatcodes.
        // Multisig creation, buffer upload, proposal, voting and execution use transactions.
        let _: Value = fixture
            .rpc
            .send(
                RpcRequest::Custom {
                    method: "surfnet_writeProgram",
                },
                json!([
                    squads_program.to_string(),
                    hex(&squads_binary),
                    0,
                    fixture.proposer.pubkey().to_string()
                ]),
            )
            .await?;
        let _: Value = fixture
            .rpc
            .send(
                RpcRequest::Custom {
                    method: "surfnet_writeProgram",
                },
                json!([
                    program.to_string(),
                    hex(&fixture.binary),
                    0,
                    vault.to_string()
                ]),
            )
            .await?;
        let global_config = squads::state::ProgramConfig {
            authority: fixture.proposer.pubkey(),
            multisig_creation_fee: 0,
            treasury: fixture.voter.pubkey(),
            _reserved: [0; 64],
        };
        let mut data = Vec::new();
        global_config.try_serialize(&mut data)?;
        let account = Account {
            lamports: fixture
                .rpc
                .get_minimum_balance_for_rent_exemption(data.len())
                .await?,
            data,
            owner: squads_program,
            executable: false,
            rent_epoch: 0,
        };
        fixture
            .set_account(get_program_config_pda(Some(&squads_program)).0, &account)
            .await?;
        let create = Instruction {
            program_id: squads_program,
            accounts: squads::accounts::MultisigCreateV2 {
                program_config: get_program_config_pda(Some(&squads_program)).0,
                treasury: fixture.voter.pubkey(),
                multisig,
                create_key: seed.pubkey(),
                creator: fixture.proposer.pubkey(),
                system_program: system_program::id(),
            }
            .to_account_metas(None),
            data: squads::instruction::MultisigCreateV2 {
                args: squads::MultisigCreateArgsV2 {
                    config_authority: None,
                    threshold: 1,
                    time_lock: 0,
                    rent_collector: None,
                    memo: None,
                    members: vec![
                        Member {
                            key: fixture.proposer.pubkey(),
                            permissions: Permissions::from_vec(&[Permission::Initiate]),
                        },
                        Member {
                            key: fixture.voter.pubkey(),
                            permissions: Permissions::from_vec(&[
                                Permission::Initiate,
                                Permission::Vote,
                                Permission::Execute,
                            ]),
                        },
                    ],
                },
            }
            .data(),
        };
        let blockhash = fixture.rpc.get_latest_blockhash().await?;
        let transaction = Transaction::new_signed_with_payer(
            &[create],
            Some(&fixture.proposer.pubkey()),
            &[&fixture.proposer, &seed],
            blockhash,
        );
        fixture
            .rpc
            .send_and_confirm_transaction(&transaction)
            .await
            .context("Create real Squads multisig")?;
        println!(
            "Surfpool ready; Swig bytes={}, sha256={:x}; Squads sha256={:x}",
            fixture.binary.len(),
            Sha256::digest(&fixture.binary),
            Sha256::digest(&squads_binary)
        );
        Ok(fixture)
    }

    pub(super) async fn set_account(&self, address: Pubkey, account: &Account) -> Result<()> {
        let _: Value = self.rpc.send(RpcRequest::Custom { method: "surfnet_setAccount" }, json!([address.to_string(), {
            "lamports": account.lamports, "data": hex(&account.data), "owner": account.owner.to_string(),
            "executable": account.executable, "rentEpoch": account.rent_epoch,
        }])).await?;
        Ok(())
    }

    pub(super) fn cli(
        &self,
        command: &str,
        binary: &Path,
        buffer: Option<Pubkey>,
        index: u64,
    ) -> Result<Output> {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_swig-release"));
        cli.env_clear()
            .env("SOLANA_RPC_URL", &self.config.rpc_url)
            .env(
                "PROPOSER_KEYPAIR",
                serde_json::to_string(&self.proposer.to_bytes().as_slice())?,
            )
            .env("SQUADS_PROGRAM_ID", self.config.squads_program.to_string())
            .env("SQUADS_MULTISIG_ADDRESS", self.config.multisig.to_string())
            .env("SQUADS_VAULT_INDEX", self.config.vault_index.to_string())
            .env("SWIG_PROGRAM_ID", self.config.program.to_string())
            .arg(command)
            .arg("--binary")
            .arg(binary);
        if let Some(buffer) = buffer {
            cli.args([
                "--buffer",
                &buffer.to_string(),
                "--transaction-index",
                &index.to_string(),
                "--source-commit",
                SOURCE_COMMIT,
                "--tag",
                "upgrade-surfpool-test",
            ]);
        }
        Ok(cli.output()?)
    }

    pub(super) fn upload_buffer(&self) -> Result<Pubkey> {
        let buffer = Keypair::new();
        let payer_path = self.directory.path().join("payer.json");
        let buffer_path = self.directory.path().join("buffer.json");
        fs::write(
            &payer_path,
            serde_json::to_vec(&self.proposer.to_bytes().as_slice())?,
        )?;
        fs::write(
            &buffer_path,
            serde_json::to_vec(&buffer.to_bytes().as_slice())?,
        )?;
        let solana = env::var("SOLANA_TEST_CLI").unwrap_or_else(|_| "solana".into());
        let output = Command::new(solana)
            .args(["program", "write-buffer"])
            .arg(&self.binary_path)
            .args([
                "--url",
                &self.config.rpc_url,
                "--commitment",
                "confirmed",
                "--use-rpc",
                "--max-sign-attempts",
                "3",
                "--max-len",
                &self.binary.len().to_string(),
            ])
            .arg("--keypair")
            .arg(&payer_path)
            .arg("--buffer")
            .arg(&buffer_path)
            .output()?;
        ensure!(
            output.status.success(),
            "Solana buffer upload failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(buffer.pubkey())
    }

    pub(super) async fn assert_rejected_without_mutation(
        &self,
        command: &str,
        binary: &Path,
        buffer: Pubkey,
        index: u64,
        expected: &str,
    ) -> Result<()> {
        let addresses = [
            buffer,
            self.config.multisig,
            self.proposer.pubkey(),
            get_transaction_pda(
                &self.config.multisig,
                index,
                Some(&self.config.squads_program),
            )
            .0,
            get_proposal_pda(
                &self.config.multisig,
                index,
                Some(&self.config.squads_program),
            )
            .0,
        ];
        let before = self.rpc.get_multiple_accounts(&addresses).await?;
        let signatures = self
            .rpc
            .get_signatures_for_address(&self.proposer.pubkey())
            .await?;
        let output = self.cli(
            command,
            binary,
            (command == "propose").then_some(buffer),
            index,
        )?;
        assert!(!output.status.success(), "Expected rejection: {expected}");
        assert!(
            output.stdout.is_empty(),
            "Rejected command emitted a receipt"
        );
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains(expected), "Expected {expected}, got {error}");
        assert_eq!(
            self.rpc.get_multiple_accounts(&addresses).await?,
            before,
            "Rejection mutated accounts"
        );
        assert_eq!(
            self.rpc
                .get_signatures_for_address(&self.proposer.pubkey())
                .await?
                .len(),
            signatures.len(),
            "Rejection submitted a transaction"
        );
        println!("PASS rejection with zero submissions: {expected}");
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
