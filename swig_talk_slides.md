# SWIG Smart Wallet: Engineering for Efficiency

---

## Slide 1: Title

SWIG Smart Wallet: Engineering for Efficiency

---

## Slide 2: Introduction

Hi, I'm Tracy from Anagram!

-   Part of the build team, doing all things Solana (and then some)
-   Excited to share how we engineered SWIG for efficiency on Solana

---

## Slide 3: The Evolution of Wallets

From Keypairs to Smart Wallets

-   Traditional wallets: just keypairs
-   Smart wallets: on-chain programs with programmable rules

---

## Slide 4: Why Solana?

Solana's Advantages for Smart Wallets

-   Account-Based Architecture
-   Composability
-   Transaction Speed & Cost
-   Programmability

---

## Slide 5: Introducing SWIG

What is SWIG?

-   Programmable smart wallet protocol
-   Role-based permission system
-   Multiple authorities & fine-grained actions
-   Sub-accounts for isolation
-   Multiple authentication methods (Ed25519, Secp256k1 social / zk login coming soon)

---

## Slide 6: SWIG Architecture

Roles, Authorities, Actions, Sub-Accounts

-   Multiple authorities with roles
-   Actions & permissions per role
-   Isolated sub-accounts
-   Programmable control (Ed25519, Secp256k1, sessions)

---

## Slide 7: Permission System

Fine-Grained Permissions

-   SOL/token transfer limits (one-time/recurring)
-   Program-specific permissions
-   Full wallet/staking permissions
-   Authority & sub-account management

---

## Slide 8: Use Cases

What Can You Build with SWIG?

-   Subscription management
-   Time-based authorizations
-   Hot wallets with program limits
-   Social/ZK login integration
-   DAO treasury management

---

## Slide 9: Technical Innovations

Engineering for Efficiency

-   Pinocchio runtime: low compute unit usage
-   Zero-copy design: direct storage access

---

## Slide 9a: Account Classification Optimization

Account Classification Optimization

-   All accounts are classified up front before instruction execution
-   Avoids repeated ownership/type checks during processing
-   Saves compute units and improves performance
-   Enables efficient permission enforcement

```rust
// program/src/lib.rs
unsafe fn execute(
    ctx: &mut InstructionContext,
    accounts: &mut [MaybeUninit<AccountInfo>],
    account_classification: &mut [MaybeUninit<AccountClassification>],
) -> Result<(), ProgramError> {
    // ...
    while let Ok(acc) = ctx.next_account() {
        let classification = match &acc {
            MaybeAccount::Account(account) => {
                classify_account(index, account, accounts, program_scope_cache.as_ref())?
            },
            // ...
        };
        account_classification[index].write(classification);
        // ...
        index += 1;
    }
    // ...
}
```

---

## Slide 9b: Instruction Compression

Instruction Compression: Efficient Transaction Packing

-   Compact encoding of instructions for lower compute and transaction size
-   Enables batching and complex workflows in a single transaction
-   Major performance win for Solana programs

> [At this point, I'll leave the slides and open the Solana Explorer to show a real mainnet Jupiter swap using SWIG:](https://explorer.solana.com/tx/2NC1YvDu259mzwEraF25N1wkFAuQpmf73GunTmUtTb872SUFYY3yrv4545fBeKArQVm3pAyMrzt5D6WePNnuSVaM)

```rust
// instructions/src/compact_instructions.rs
pub struct CompactInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

impl CompactInstructions {
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.inner_instructions.len() as u8];
        for ix in self.inner_instructions.iter() {
            bytes.push(ix.program_id_index);
            bytes.push(ix.accounts.len() as u8);
            bytes.extend(ix.accounts.iter());
            bytes.extend((ix.data.len() as u16).to_le_bytes());
            bytes.extend(ix.data.iter());
        }
        bytes
    }
}
```

---

## Slide 10: Main Instructions

How Do You Use SWIG?

-   Create wallet
-   Add/remove authorities
-   Sign/execute transactions
-   Create session keys
-   Manage sub-accounts

---

## Slide 11: Security Features

Security by Design

-   Role-based access control
-   Multi-signature support
-   Session key management
-   Spending/program limits
-   On-curve public key validation

---

## Slide 12: Conclusion

The Future of Efficient Smart Wallets

-   Advanced authorization
-   High performance
-   Secure, programmable control
-   For developers, DAOs, institutions
-   Thank you! Questions?

---

## Slide 13: It's a SWIG world and we're just living in it

-   Welcome to the future of efficient, programmable wallets
-   The world is changing—let's SWIG it!
