use pinocchio::program_error::ProgramError;

const SIWS_HEADER_SUFFIX: &str = " wants you to sign in with your Solana account:";
const FIELD_URI_PREFIX: &str = "URI: ";
const FIELD_VERSION_PREFIX: &str = "Version: ";
const FIELD_CHAIN_ID_PREFIX: &str = "Chain ID: ";
const FIELD_NONCE_PREFIX: &str = "Nonce: ";
const FIELD_ISSUED_AT_PREFIX: &str = "Issued At: ";
const FIELD_EXPIRATION_TIME_PREFIX: &str = "Expiration Time: ";
const FIELD_NOT_BEFORE_PREFIX: &str = "Not Before: ";
const FIELD_REQUEST_ID_PREFIX: &str = "Request ID: ";
const FIELD_RESOURCES: &str = "Resources:";

pub(super) struct ParsedSiwsChallenge<'a> {
    pub(super) address: &'a str,
    pub(super) resources: Vec<&'a str>,
}

pub(super) fn parse_siws_challenge(
    challenge: &[u8],
) -> Result<ParsedSiwsChallenge<'_>, ProgramError> {
    let challenge_str =
        core::str::from_utf8(challenge).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut lines: Vec<&str> = challenge_str
        .split('\n')
        .map(trim_optional_carriage_return)
        .collect();
    while matches!(lines.last(), Some(line) if line.is_empty()) {
        lines.pop();
    }

    if lines.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let Some(domain) = lines[0].strip_suffix(SIWS_HEADER_SUFFIX) else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if domain.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let address = lines[1];
    if !is_valid_solana_address(address) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut cursor = 2usize;
    let mut resources = Vec::new();
    if cursor < lines.len() {
        if !lines[cursor].is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        cursor += 1;

        if cursor < lines.len() && !is_advanced_field_start(lines[cursor]) {
            if lines[cursor].is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            cursor += 1;

            if cursor == lines.len() {
                return Ok(ParsedSiwsChallenge { address, resources });
            }

            if !lines[cursor].is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            cursor += 1;
        }

        if cursor < lines.len() {
            resources = parse_advanced_fields(&lines[cursor..])?;
        }
    }

    Ok(ParsedSiwsChallenge { address, resources })
}

fn parse_advanced_fields<'a>(lines: &[&'a str]) -> Result<Vec<&'a str>, ProgramError> {
    let mut resources = Vec::new();
    let mut cursor = 0usize;
    let mut min_field_index = 0usize;

    while cursor < lines.len() {
        let line = lines[cursor];
        if min_field_index <= 0 && line.starts_with(FIELD_URI_PREFIX) {
            if line[FIELD_URI_PREFIX.len()..].is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 1;
            cursor += 1;
            continue;
        }
        if min_field_index <= 1 && line.starts_with(FIELD_VERSION_PREFIX) {
            if &line[FIELD_VERSION_PREFIX.len()..] != "1" {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 2;
            cursor += 1;
            continue;
        }
        if min_field_index <= 2 && line.starts_with(FIELD_CHAIN_ID_PREFIX) {
            let chain_id = &line[FIELD_CHAIN_ID_PREFIX.len()..];
            if !is_valid_chain_id(chain_id) {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 3;
            cursor += 1;
            continue;
        }
        if min_field_index <= 3 && line.starts_with(FIELD_NONCE_PREFIX) {
            let nonce = &line[FIELD_NONCE_PREFIX.len()..];
            if !is_valid_nonce(nonce) {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 4;
            cursor += 1;
            continue;
        }
        if min_field_index <= 4 && line.starts_with(FIELD_ISSUED_AT_PREFIX) {
            if line[FIELD_ISSUED_AT_PREFIX.len()..].is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 5;
            cursor += 1;
            continue;
        }
        if min_field_index <= 5 && line.starts_with(FIELD_EXPIRATION_TIME_PREFIX) {
            if line[FIELD_EXPIRATION_TIME_PREFIX.len()..].is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 6;
            cursor += 1;
            continue;
        }
        if min_field_index <= 6 && line.starts_with(FIELD_NOT_BEFORE_PREFIX) {
            if line[FIELD_NOT_BEFORE_PREFIX.len()..].is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            min_field_index = 7;
            cursor += 1;
            continue;
        }
        if min_field_index <= 7 && line.starts_with(FIELD_REQUEST_ID_PREFIX) {
            min_field_index = 8;
            cursor += 1;
            continue;
        }
        if min_field_index <= 8 && line == FIELD_RESOURCES {
            cursor += 1;
            while cursor < lines.len() {
                let Some(resource) = lines[cursor].strip_prefix("- ") else {
                    return Err(ProgramError::InvalidInstructionData);
                };
                if resource.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                resources.push(resource);
                cursor += 1;
            }
            return Ok(resources);
        }

        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(resources)
}

#[inline(always)]
fn trim_optional_carriage_return(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

#[inline(always)]
fn is_advanced_field_start(line: &str) -> bool {
    line.starts_with(FIELD_URI_PREFIX)
        || line.starts_with(FIELD_VERSION_PREFIX)
        || line.starts_with(FIELD_CHAIN_ID_PREFIX)
        || line.starts_with(FIELD_NONCE_PREFIX)
        || line.starts_with(FIELD_ISSUED_AT_PREFIX)
        || line.starts_with(FIELD_EXPIRATION_TIME_PREFIX)
        || line.starts_with(FIELD_NOT_BEFORE_PREFIX)
        || line.starts_with(FIELD_REQUEST_ID_PREFIX)
        || line == FIELD_RESOURCES
}

#[inline(always)]
fn is_valid_chain_id(chain_id: &str) -> bool {
    matches!(
        chain_id,
        "mainnet"
            | "testnet"
            | "devnet"
            | "localnet"
            | "solana:mainnet"
            | "solana:testnet"
            | "solana:devnet"
    )
}

#[inline(always)]
fn is_valid_nonce(nonce: &str) -> bool {
    nonce.len() >= 8 && nonce.bytes().all(|value| value.is_ascii_alphanumeric())
}

#[inline(always)]
fn is_valid_solana_address(address: &str) -> bool {
    let len = address.len();
    (32..=44).contains(&len) && address.bytes().all(is_base58_character)
}

#[inline(always)]
fn is_base58_character(value: u8) -> bool {
    matches!(
        value,
        b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z'
    )
}

#[cfg(test)]
mod tests {
    use super::parse_siws_challenge;

    #[test]
    fn parses_challenge_address_and_resources() {
        let challenge = b"example.com wants you to sign in with your Solana account:\n3KMf9P7w2nQx5R8tUvYcBdEghJkMNpQrS\n\nSign in to Swig\n\nURI: https://example.com\nVersion: 1\nChain ID: solana:devnet\nNonce: abcdef12\nIssued At: 2026-01-01T00:00:00Z\nResources:\n- urn:swig:v1:swig:swig123\n- urn:swig:v1:swig_wallet_address:3KMf9P7w2nQx5R8tUvYcBdEghJkMNpQrS\n- urn:swig:v1:swig_program:program123\n- urn:swig:v1:role_id:1\n- urn:swig:v1:scope:ProgramScope";
        let parsed = match parse_siws_challenge(challenge) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parse_siws_challenge should succeed: {error:?}"),
        };
        assert_eq!(parsed.address, "3KMf9P7w2nQx5R8tUvYcBdEghJkMNpQrS");
        assert_eq!(parsed.resources.len(), 5);
    }

    #[test]
    fn rejects_out_of_order_advanced_fields() {
        let invalid = b"example.com wants you to sign in with your Solana account:\n3KMf9P7w2nQx5R8tUvYcBdEghJkMNpQrS\n\nNonce: abcdef12\nVersion: 1";
        assert!(parse_siws_challenge(invalid).is_err());
    }
}
