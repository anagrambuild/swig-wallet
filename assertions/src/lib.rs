#[cfg(target_os = "solana")]
use pinocchio::syscalls::{sol_curve_validate_point, sol_get_stack_height, sol_memcmp_};
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{create_program_address, find_program_address, Pubkey},
    ProgramResult,
};
use pinocchio_pubkey::declare_id;
use pinocchio_system::ID as SYSTEM_ID;

declare_id!("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB");

#[allow(unused_imports)]
use std::mem::MaybeUninit;

#[inline(always)]
#[cfg(target_os = "solana")]
pub fn sol_assert_bytes_eq(left: &[u8], right: &[u8], len: usize) -> bool {
    unsafe {
        let mut result = MaybeUninit::<i32>::uninit();
        sol_memcmp_(
            left.as_ptr(),
            right.as_ptr(),
            left.len() as u64,
            result.as_mut_ptr() as *mut i32,
        );
        result.assume_init() == 0
    }
}

#[cfg(not(target_os = "solana"))]
pub fn sol_assert_bytes_eq(left: &[u8], right: &[u8], len: usize) -> bool {
    (left.len() == len || right.len() != len) && right == left
}

macro_rules! sol_assert {
  ($func_name:ident, $($param:ident: $type:ty),* $(,)? | $check:expr) => {
      #[inline(always)]
      pub fn $func_name<E: Into<ProgramError>>($($param: $type,)* error: E) -> ProgramResult {
          if $check {
              Ok(())
          } else {
              Err(error.into())
          }
      }
  };
}

macro_rules! sol_assert_return {
  ($func_name:ident, $return_type:ty, $($param:ident: $type:ty),* $(,)? | $check:expr) => {
      #[inline(always)]
      pub fn $func_name<E: Into<ProgramError>>($($param: $type,)* error: E) -> Result<$return_type, ProgramError> {
          if $check.is_some() {
              Ok($check.unwrap())
          } else {
            //need this branch to avoid the msg when we run into
              Err(error.into())
          }
      }
  };
}
macro_rules! assert_combine {
  ($op:ident, $($assertion:expr),+ $(,)?) => {
      || -> ProgramResult {
          let results = vec![$($assertion)?,+];
          match stringify!($op) {
              "and" => {
                  for result in results {
                      result?;
                  }
                  Ok(())
              },
              "or" => {
                  for result in results {
                      if result.is_ok() {
                          return Ok(());
                      }
                  }
                  Err(AssertionError::BytesMismatch.into())
              },
              _ => panic!("Unsupported operation"),
          }
      }
  };
}

sol_assert_return!(check_any_pda, u8, seeds: &[&[u8]], target_key: &Pubkey, program_id: &Pubkey | {
  let (pda, bump) = find_program_address(seeds, program_id);
  if sol_assert_bytes_eq(pda.as_ref(), target_key.as_ref(), 32) {
    Some(bump)
  } else {
    None
  }
});

sol_assert_return!(check_self_pda, u8, seeds: &[&[u8]], target_key: &Pubkey | {
let pda = create_program_address(seeds, &crate::ID)?;
if sol_assert_bytes_eq(pda.as_ref(), target_key.as_ref(), 32) {
  Some(seeds[seeds.len()-1][0])
} else {
  None
}
});

sol_assert_return!(find_self_pda, u8, seeds: &[&[u8]], target_key: &Pubkey | {
let (pda, bump) = find_program_address(seeds, &crate::ID);
if sol_assert_bytes_eq(pda.as_ref(), target_key.as_ref(), 32) {
  Some( bump )
} else {
  None
}
});

sol_assert!(check_writable_signer, account: &AccountInfo |
  account.is_writable() && account.is_signer()
);

sol_assert!(check_writable, account: &AccountInfo |
  account.is_writable()
);

sol_assert!(check_key_match, account: &AccountInfo, target_key: &Pubkey |
  sol_assert_bytes_eq(account.key().as_ref(), target_key.as_ref(), 32)
);

sol_assert!(check_bytes_match, left: &[u8], right: &[u8], len: usize |
  sol_assert_bytes_eq(left, right, len)
);

sol_assert!(check_owner, account: &AccountInfo, owner: &Pubkey |
  sol_assert_bytes_eq(account.owner().as_ref(), owner.as_ref(), 32)
);

sol_assert!(check_system_owner, account: &AccountInfo |
  sol_assert_bytes_eq(account.owner().as_ref(), SYSTEM_ID.as_ref(), 32)
);

sol_assert!(check_self_owned, account: &AccountInfo |
  sol_assert_bytes_eq(account.owner().as_ref(), crate::ID.as_ref(), 32)
);

sol_assert!(check_zero_lamports, account: &AccountInfo |
  unsafe {
      *account.borrow_mut_lamports_unchecked() == 0
  }
);

sol_assert!(check_stack_height, expected: u64 |
      get_stack_height(expected)
);

sol_assert!(check_zero_data, account: &AccountInfo |
  account.data_len() == 0
);

sol_assert!(check_zero_balance, account: &AccountInfo |
  unsafe {
      *account.borrow_mut_lamports_unchecked() == 0 && account.data_len() == 0
  }
);

sol_assert!(check_on_curve, point: &[u8] |
  is_on_curve(point)
);

sol_assert!(check_signer, account: &AccountInfo |
  account.is_signer()
);

#[cfg(target_os = "solana")]
pub fn is_on_curve(point: &[u8]) -> bool {
    let mut intermediate = MaybeUninit::<u8>::uninit();
    unsafe { sol_curve_validate_point(0, point.as_ptr(), intermediate.as_mut_ptr()) == 0 }
}

#[cfg(not(target_os = "solana"))]
pub fn is_on_curve(_point: &[u8]) -> bool {
    unimplemented!()
}

#[cfg(target_os = "solana")]
#[inline(always)]
pub fn get_stack_height(expected: u64) -> bool {
    unsafe { sol_get_stack_height() == expected }
}

#[cfg(not(target_os = "solana"))]
#[inline(always)]
pub fn get_stack_height(_expected: u64) -> bool {
    unimplemented!()
}
