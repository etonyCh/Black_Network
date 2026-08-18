#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use core::mem;
use netsentinel_capture_common::PacketLog;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[xdp]
pub fn netsentinel_capture_ebpf(ctx: XdpContext) -> u32 {
    match try_netsentinel_capture_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_netsentinel_capture_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto } as u8;

    // Simplification for length
    let length = (ctx.data_end() - ctx.data()) as u32;

    let mut unencrypted = 0;

    if unsafe { (*ipv4hdr).proto } == IpProto::Tcp {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
        let dst_port = u16::from_be(unsafe { (*tcphdr).dest });
        let src_port = u16::from_be(unsafe { (*tcphdr).source });
        if dst_port == 80 || src_port == 80 || dst_port == 21 || dst_port == 23 {
            unencrypted = 1;
        }
    } else if unsafe { (*ipv4hdr).proto } == IpProto::Udp {
        let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
        let dst_port = u16::from_be(unsafe { (*udphdr).dest });
        let src_port = u16::from_be(unsafe { (*udphdr).source });
        if dst_port == 53 || src_port == 53 {
            unencrypted = 1; // DNS
        }
    }

    let log = PacketLog {
        src_addr,
        dst_addr,
        protocol,
        padding: [0; 3],
        length,
        unencrypted,
        padding2: [0; 3],
    };

    EVENTS.output(&ctx, &log, 0);

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
