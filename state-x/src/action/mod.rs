pub mod sol_limit;
pub mod sol_recurring_limit;

use pinocchio::program_error::ProgramError;

use crate::Transmutable;

#[repr(C)]
pub struct Action {
    /// Data section.
    ///  * [0] type
    ///  * [1] length
    ///  * [2..3] boundary
    data: [u16; 4],
}

impl Transmutable for Action {
    const LEN: usize = core::mem::size_of::<Action>();
}

impl Action {
    pub fn permission(&self) -> Result<Permission, ProgramError> {
        Permission::try_from(self.data[0])
    }

    pub fn length(&self) -> u16 {
        self.data[1]
    }

    pub fn boundary(&self) -> u32 {
        // SAFETY: `data` is to have a length of 8 bytes, where the last 4 bytes
        // are the boundary.
        u32::from_le_bytes(unsafe { *(self.data.as_ptr().add(2) as *const [u8; 4]) })
    }
}

#[derive(Default, PartialEq)]
#[repr(u16)]
pub enum Permission {
    #[default]
    None,
    SolLimit,
    SolRecurringLimit,
    Program,
    TokenLimit,
    TokenRecurringLimit,
    TokensLimit,
    TokensRecurringLimit,
    All,
    ManageAuthority,
    SubAccount,
}

impl TryFrom<u16> for Permission {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            // SAFETY: `value` is guaranteed to be in the range of the enum variants.
            0..=10 => Ok(unsafe { core::mem::transmute::<u16, Permission>(value) }),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Trait for representing action data.
pub trait Actionable<'a> {
    const TYPE: Permission;

    fn from_bytes(bytes: &'a [u8]) -> &'a Self;

    fn validate(&mut self);
}
