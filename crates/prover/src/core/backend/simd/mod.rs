use super::Backend;

pub mod accumulation;
pub mod bit_reverse;
pub mod circle;
pub mod cm31;
pub mod column;
pub mod fft;
pub mod fri;
pub mod m31;
pub mod qm31;
pub mod quotients;
pub mod sha256;
mod utils;

#[derive(Copy, Clone, Debug)]
pub struct SimdBackend;

impl Backend for SimdBackend {}
