// use super::{AuthorityData, AuthorityDataMut, AuthorityType};

// pub struct Secp256k1Authority {
//     pub public_key: [u8; 64],
// }

// impl<'a> AuthorityData<'a> for Secp256k1Authority {
//     const TYPE: AuthorityType = AuthorityType::Secp256k1;

//     fn size(&self) -> usize {
//         self.public_key.len()
//     }

//     fn load_from_bytes(data: &'a [u8]) -> Self {
//         Self {
//             public_key: data.try_into().unwrap(),
//         }
//     }

//     fn into_bytes(self) -> Vec<u8> {
//         self.public_key.to_vec()
//     }
// }

// impl<'a> AuthorityDataMut<'a> for Secp256k1Authority {
//     fn load_from_bytes_mut(data: &'a mut [u8]) -> Self {
//         Self {
//             public_key: data.try_into().unwrap(),
//         }
//     }
// }

// pub struct Secp256k1SessionAuthority {
//     pub public_key: [u8; 64],
//     pub session_public_key: [u8; 32],
//     pub expires_at: u64,
// }

// impl<'a> AuthorityData<'a> for Secp256k1SessionAuthority {
//     const TYPE: AuthorityType = AuthorityType::Secp256k1Session;

//     fn size(&self) -> usize {
//         self.public_key.len() + self.session_public_key.len() + 8
//     }

//     fn load_from_bytes(data: &'a [u8]) -> Self {
//         let public_key = data[0..64].try_into().unwrap();
//         let session_public_key = data[64..96].try_into().unwrap();
//         let expires_at = u64::from_le_bytes(data[96..104].try_into().unwrap());
//         Self {
//             public_key,
//             session_public_key,
//             expires_at,
//         }
//     }

//     fn into_bytes(self) -> Vec<u8> {
//         let mut bytes = Vec::with_capacity(self.size());
//         bytes.extend_from_slice(&self.public_key);
//         bytes.extend_from_slice(&self.session_public_key);
//         bytes.extend_from_slice(&self.expires_at.to_le_bytes());
//         bytes
//     }
// }

// impl<'a> AuthorityDataMut<'a> for Secp256k1SessionAuthority {
//     fn load_from_bytes_mut(data: &'a mut [u8]) -> Self {
//         let public_key = data[0..64].try_into().unwrap();
//         let session_public_key = data[64..96].try_into().unwrap();
//         let expires_at = u64::from_le_bytes(data[96..104].try_into().unwrap());
//         Self {
//             public_key,
//             session_public_key,
//             expires_at,
//         }
//     }
// }
