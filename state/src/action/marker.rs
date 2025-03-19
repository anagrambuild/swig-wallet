/// Macro to create permission marker types that implement the Actionable trait
///
/// # Arguments
/// * `name` - The name of the struct to create
/// * `permission_type` - The PermissionType variant to use
macro_rules! impl_permission_marker {
    ($name:ident, $permission_type:expr) => {
        pub struct $name {}
        impl $name {}

        impl<'a> Actionable<'a> for $name {
            const TYPE: PermissionType = $permission_type;

            fn size(&self) -> usize {
                1
            }

            fn load_from_bytes(data: &[u8]) -> Result<Self, SwigStateError> {
                if data.len() != 1 {
                    return Err(SwigStateError::InvalidAction);
                }
                let ty = PermissionType::from_u8(data[0]);
                if ty == PermissionType::None {
                    return Err(SwigStateError::InvalidAction);
                }
                if ty != Self::TYPE {
                    return Err(SwigStateError::InvalidAction);
                }
                Ok(Self {})
            }

            fn load_from_bytes_mut(data: &mut [u8]) -> Result<Self, SwigStateError> {
                Self::load_from_bytes(data)
            }

            fn into_bytes(self) -> Vec<u8> {
                vec![Self::TYPE as u8]
            }
        }
    };
}
