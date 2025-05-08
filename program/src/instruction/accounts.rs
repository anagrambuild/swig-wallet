use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

use crate::error::SwigError;

pub struct Context<T> {
    pub accounts: T,
}

// Existing account structures

pub struct CreateV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

pub struct SignV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

pub struct AddAuthorityV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

pub struct RemoveAuthorityV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

pub struct CreateSessionV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

// New account structures for sub-account functionality

pub struct CreateSubAccountV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub sub_account: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

impl<'a> CreateSubAccountV1Accounts<'a> {
    pub fn to_account_infos(&self) -> Vec<&'a AccountInfo<'a>> {
        vec![self.swig, self.payer, self.sub_account, self.system_program]
    }
}

pub struct WithdrawFromSubAccountV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub sub_account: &'a AccountInfo<'a>,
    pub token_account: Option<&'a AccountInfo<'a>>,
}

impl<'a> WithdrawFromSubAccountV1Accounts<'a> {
    pub fn to_account_infos(&self) -> Vec<&'a AccountInfo<'a>> {
        let mut accounts = vec![self.swig, self.payer, self.sub_account];
        if let Some(token_account) = self.token_account {
            accounts.push(token_account);
        }
        accounts
    }
}

pub struct SubAccountSignV1Accounts<'a> {
    pub sub_account: &'a AccountInfo<'a>,
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

impl<'a> SubAccountSignV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 4 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                sub_account: &accounts[0],
                swig: &accounts[1],
                payer: &accounts[2],
                system_program: &accounts[3],
            },
        })
    }
}

pub struct ToggleSubAccountV1Accounts<'a> {
    pub swig: &'a AccountInfo<'a>,
    pub payer: &'a AccountInfo<'a>,
    pub sub_account: &'a AccountInfo<'a>,
}

impl<'a> ToggleSubAccountV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 3 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                sub_account: &accounts[2],
            },
        })
    }
}

// Implementation of context() method for all account structures

impl<'a> CreateV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 3 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                system_program: &accounts[2],
            },
        })
    }
}

impl<'a> SignV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 3 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                system_program: &accounts[2],
            },
        })
    }
}

impl<'a> AddAuthorityV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 3 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                system_program: &accounts[2],
            },
        })
    }
}

impl<'a> RemoveAuthorityV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 3 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                system_program: &accounts[2],
            },
        })
    }
}

impl<'a> CreateSessionV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 3 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                system_program: &accounts[2],
            },
        })
    }
}

impl<'a> CreateSubAccountV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        if accounts.len() < 4 {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                sub_account: &accounts[2],
                system_program: &accounts[3],
            },
        })
    }
}

impl<'a> WithdrawFromSubAccountV1Accounts<'a> {
    pub fn context(accounts: &'a [AccountInfo]) -> Result<Context<Self>, ProgramError> {
        let min_accounts = 3;
        let has_token_account = accounts.len() > min_accounts;

        if accounts.len() < min_accounts {
            return Err(SwigError::InvalidAccountsLength.into());
        }

        Ok(Context {
            accounts: Self {
                swig: &accounts[0],
                payer: &accounts[1],
                sub_account: &accounts[2],
                token_account: if has_token_account {
                    Some(&accounts[3])
                } else {
                    None
                },
            },
        })
    }
}
