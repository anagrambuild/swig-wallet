use pinocchio::instruction::Seed;

pub const DEVELOPER_ACCOUNT_SEED: &[u8] = b"developer-account";

#[inline(always)]
pub fn developer_account_seeds(developer_account_id: &[u8; 32]) -> [&[u8]; 2] {
    [DEVELOPER_ACCOUNT_SEED, developer_account_id]
}

#[inline(always)]
pub fn developer_account_seeds_with_bump<'a>(
    developer_account_id: &'a [u8; 32],
    bump: &'a [u8; 1],
) -> [&'a [u8]; 3] {
    [DEVELOPER_ACCOUNT_SEED, developer_account_id, bump]
}

pub fn developer_account_signer<'a>(
    developer_account_id: &'a [u8; 32],
    bump: &'a [u8; 1],
) -> [Seed<'a>; 3] {
    [
        DEVELOPER_ACCOUNT_SEED.into(),
        developer_account_id.as_ref().into(),
        bump.as_ref().into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeds_match_the_documented_literal() {
        let id = [9u8; 32];
        let bump = [254u8];
        assert_eq!(
            developer_account_seeds(&id),
            [b"developer-account".as_ref(), &id]
        );
        assert_eq!(
            developer_account_seeds_with_bump(&id, &bump),
            [b"developer-account".as_ref(), &id, &bump]
        );
    }
}
