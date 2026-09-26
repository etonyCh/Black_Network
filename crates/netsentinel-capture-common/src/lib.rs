#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub unencrypted: u8,
    pub length: u32,
    pub _pad: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
