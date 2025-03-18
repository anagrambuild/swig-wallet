use bytemuck::Pod;

pub trait ZeroCopy<'a, T: Pod>
where
    Self: Pod,
{
    #[inline]
    fn load_prefix(data: &'a [u8]) -> Result<(&'a Self, &'a [u8]), bytemuck::PodCastError> {
        let (data, remaining) = data.split_at(std::mem::size_of::<Self>());
        let item = bytemuck::try_from_bytes(data)?;
        Ok((item, remaining))
    }

    #[inline]
    fn load(data: &'a [u8]) -> Result<&'a Self, bytemuck::PodCastError> {
        bytemuck::try_from_bytes(data)
    }

    #[inline]
    fn load_mut(data: &'a mut [u8]) -> Result<&'a mut Self, bytemuck::PodCastError> {
        bytemuck::try_from_bytes_mut(data)
    }

    fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(self)
    }
}
