#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub protocol: u8,
    pub padding: [u8; 3],
    pub length: u32,
    pub unencrypted: u8,
    pub padding2: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
