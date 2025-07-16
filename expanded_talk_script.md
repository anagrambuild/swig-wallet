# SWIG Smart Wallet: Engineering for Efficiency

---

### Slide 1: Title

**[On Slide: SWIG Smart Wallet: Engineering for Efficiency]**

**Speaker:**
Welcome everyone! Today, we're diving into the future of efficient, programmable wallets on Solana with SWIG. This talk is all about how we engineered for efficiency at every layer.

---

### Slide 2: Introduction

**[On Slide: Introduction]**

**Speaker:**
Hi, I'm Tracy from Anagram! I'm part of the build team (we go by the Raccoons), doing all things Solana (and then some). You can find me on X at @tracy_codes and I've been building on Solana since 2021. I'm excited to share how we engineered SWIG for efficiency on Solana.

Before we dive in, I want to give a huge shoutout to the Raccoon Squad at Anagram—the SWIG core team. We're builders and Solana fanatics. Special thanks to Zubayr, who volunteered extra time to help us hit critical milestones. I'm so proud to be part of Anagram's build team.

---

### Slide 3: The Evolution of Wallets

**[On Slide: From Keypairs to Smart Wallets]**

**Speaker:**
Let's start with a simple question: What is a wallet on the blockchain? Traditionally, wallets have been just keypairs—private keys that sign transactions. But as our needs have grown, so has the technology. Enter smart wallets: on-chain programs that don't just sign, but actually manage assets and authorize transactions based on programmable rules.

**[Audience cue: Raise your hand if you've ever worried about losing your private key or wished you could set spending limits on your wallet!]**

Smart wallets are the answer. They let us embed custom logic directly on-chain, opening up new possibilities for security, usability, and collaboration.

---

### Slide 4: Why Solana?

**[On Slide: Solana's Advantages for Smart Wallets]**

**Speaker:**
Why build smart wallets on Solana? There are four main reasons:

1. **Account-Based Architecture:** Solana's model makes it easy to manage ownership and permissions.
2. **Composability:** Smart wallets can interact with any program in the ecosystem, making them universal interfaces.
3. **Transaction Speed & Cost:** Solana's high throughput and low fees make even complex authorization logic practical.
4. **Programmability:** On-chain programs let us implement sophisticated wallet logic that was previously impossible.

**[Reference: See `program/src/` and `state-x/src/` for how we leverage Solana's account model and program structure.]**

---

### Slide 5-6: Introducing SWIG

**[On Slide: What is SWIG?]**

**Speaker:**
This brings us to SWIG. SWIG is a programmable smart wallet protocol designed for advanced authorization, performance, and above all, efficiency.

At its core, SWIG implements a role-based permission system:

-   Multiple authorities can control a wallet, each with different permission levels.
-   Fine-grained actions restrict what each authority can do.
-   Sub-accounts provide isolated environments for specific purposes.
-   Multiple authentication methods, including Ed25519 and Secp256k1, are supported.

Most importantly, SWIG is the most efficient smart wallet protocol we can currently find. The main goal of SWIG was to make it as close to operating a keypair-based wallet as possible. Clocking in at just 1293 CU overhead for a SOL transfer and 2773 CU overhead for a SPL Token Transfer (1500 of that being the CPI by the way). Compared to others which come in at 50k or more CU overhead, we've worked really hard to get our protocol to where it's at today.

**[Reference: The architecture is defined in `state-x/src/swig.rs` and `state-x/src/role.rs`. The main program logic lives in `program/src/`.]
**

---

### Slide 7: SWIG Architecture

**[On Slide: Roles, Authorities, Actions, Sub-Accounts]**

**Speaker:**
Let's break down the architecture:

-   **Roles & Authorities:** Each wallet can have multiple authorities, each assigned a role. For example, you might have an owner, a manager, and a session key.
-   **Actions & Permissions:** Each role is associated with a set of actions—like transferring tokens, managing sub-accounts, or interacting with specific programs.
-   **Sub-Accounts:** These are isolated accounts managed by the main wallet, perfect for budgeting or compartmentalizing funds.
-   **Programmable Control:** SWIG supports different signing mechanisms, including Ed25519 and Secp256k1, and even session keys for temporary access.

**[Reference: See `state-x/src/authority/` and `state-x/src/action/` for implementation details.]**

---

### Slide 8: Permission System

**[On Slide: Fine-Grained Permissions]**

**Speaker:**
SWIG's permission system is highly flexible. Here are some of the action types you can configure:

-   SOL and token transfer limits (one-time or recurring)
-   Program-specific permissions
-   Full wallet or staking permissions
-   Authority management
-   Sub-account management

This means you can create a wallet that, for example, only allows a certain authority to spend up to 1 SOL per day, or only interact with a specific DEX.

**[Reference: Action types are defined in `state-x/src/action/` and enforced in `program/src/actions/`.]
**

---

### Slide 9: Use Cases

**[On Slide: What Can You Build with SWIG?]**

**Speaker:**
Let's look at some real-world use cases:

-   **Subscription Management:** Give a service permission to deduct a set amount periodically.
-   **Time-Based Authorizations:** Grant temporary access that expires automatically—great for delegation or recovery.
-   **Hot Wallets with Program Limits:** Create wallets that can only interact with specific programs, reducing risk.
-   **Social or ZK Login Integration:** Add Secp256k1 authorities for Ethereum-style or social logins.

**[Audience cue: Imagine how you could use these features in your own projects!]**

---

### Slide 10-11: Technical Optimizations

**[On Slide: Engineering for Efficiency]**

**Speaker:**
What makes SWIG special isn't just its features, but how it delivers them efficiently:

-   Pinocchio Runtime: SWIG uses Pinocchio, a lightweight, zero-dependency Solana Program framework, to minimize compute unit usage. This is a thin abstraction over Solana's syscalls, reducing overhead.
-   Zero-Copy Design: Data is accessed directly from storage, using in-place processing and compact data layouts. This means less memory usage and faster execution.
-   Some magic sprinkled in

**[Reference: See `state-x/src/swig.rs` for zero-copy patterns and `program/src/` for runtime optimizations.]**

---

### Slide 12: Account Classification Optimization

**[On Slide: Account Classification Optimization]**

**Speaker:**
Let's dive deeper into one of SWIG's key optimizations: account classification. In Solana programs, it's common to repeatedly check account types and ownership during instruction processing, which can waste compute units. SWIG solves this by classifying all accounts up front, before any instruction logic runs. This enables efficient permission enforcement and saves significant compute.

Here's a simplified version of the core loop:

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

This approach means every subsequent check is just a fast lookup, not a costly computation.

---

### Slide 13: Instruction Compression

**[On Slide: Instruction Compression: Efficient Transaction Packing]**

**Speaker:**
Another major innovation in SWIG is instruction compression. Solana transactions are limited in size and compute, so packing more logic into fewer bytes is a big win. SWIG encodes instructions in a compact format, allowing batching and complex workflows in a single transaction—another example of engineering for efficiency.

Here's a core part of the compression logic:

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

Remember what I said about the low CU overhead? Let's go take a look at a real SWIG wallet transaction that interacts with the Jupiter swap program. Notorious for having some pretty beefy transaction sizes.

**At this point, I'll leave the slides and open the Solana Explorer to show a real mainnet Jupiter swap using SWIG:**
https://explorer.solana.com/tx/2NC1YvDu259mzwEraF25N1wkFAuQpmf73GunTmUtTb872SUFYY3yrv4545fBeKArQVm3pAyMrzt5D6WePNnuSVaM

This lets us fit more actions into a single transaction, reducing cost and increasing throughput—crucial for real-world DeFi and DAO workflows.

---

### Slide 14-15: Main Instructions

**[On Slide: How Do You Use SWIG?]**

**Speaker:**
How do you use SWIG?

SWIG exposes a set of instructions for wallet and sub-account management:

-   Create a wallet
-   Add or remove authorities
-   Sign and execute transactions
-   Create session keys
-   Manage sub-accounts

**[Reference: Instruction handling is in `instructions/src/` and client interface in `interface/src/lib.rs`.]
**

---

### Slide 16: Resources

**[On Slide: Resources]**

**Speaker:**
Here are resources for working with SWIG.

-   Program Repository on GitHub
    -   Includes Program code, Rust SDK, Rust-based CLI, Rust examples
-   Typescript SDK Repository on GitHub
    -   Includes SDK and some working examples in TypeScript
-   Awesome-Swig Repository
    -   Full Integration Examples
-   Documentation & Other Resources
    -   onswig.com and build.onswig.com

---

### Slide 17: Conclusion

**[On Slide: The Future of Efficient Smart Wallets]**

**Speaker:**
To wrap up: SWIG is a new generation of smart wallet, combining advanced authorization with high performance and a relentless focus on efficiency. It's designed for developers, DAOs, institutions, and anyone who needs secure, programmable, and efficient control over their assets.

I'm excited to see what you'll build with SWIG. Thank you for your time, and I am reachable on X at tracy_codes or email at ta@anagram.xyz. You can also reach out to my colleague Liam at ld@anagram.xyz.

---
