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
        Err(_) => xdp_action::XDP_PASS,
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
    let length = (ctx.data_end() - ctx.data()) as u32;
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let eth_type = unsafe { (*ethhdr).ether_type };

    if eth_type == EtherType::Arp {
        let log = PacketLog {
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 253,
            unencrypted: 1,
            length,
            _pad: [0; 2],
        };
        EVENTS.output(&ctx, log, 0);
        return Ok(xdp_action::XDP_PASS);
    }

    if eth_type == EtherType::Ipv6 {
        let base = EthHdr::LEN;
        let nxt: *const u8 = unsafe { ptr_at(&ctx, base + 6)? };
        let shi: *const u32 = unsafe { ptr_at(&ctx, base + 8)? };
        let dhi: *const u32 = unsafe { ptr_at(&ctx, base + 24)? };
        let nh = unsafe { *nxt };
        let src_hi = u32::from_be(unsafe { *shi });
        let dst_hi = u32::from_be(unsafe { *dhi });
        let l4 = base + 40;
        let (sp, dp, clear) = unsafe { tcp_udp_ports(&ctx, l4, nh)? };
        let log = PacketLog {
            src_addr: src_hi,
            dst_addr: dst_hi,
            src_port: sp,
            dst_port: dp,
            protocol: nh,
            unencrypted: clear,
            length,
            _pad: [0; 2],
        };
        EVENTS.output(&ctx, log, 0);
        return Ok(xdp_action::XDP_PASS);
    }

    if eth_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto } as u8;
    let (sp, dp, clear) = unsafe { tcp_udp_ports(&ctx, EthHdr::LEN + Ipv4Hdr::LEN, protocol)? };
    let unencrypted = if protocol == 1 || protocol == 58 {
        1
    } else {
        clear
    };

    let log = PacketLog {
        src_addr,
        dst_addr,
        src_port: sp,
        dst_port: dp,
        protocol,
        unencrypted,
        length,
        _pad: [0; 2],
    };
    EVENTS.output(&ctx, log, 0);
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn tcp_udp_ports(ctx: &XdpContext, l4_off: usize, proto: u8) -> Result<(u16, u16, u8), ()> {
    if proto == IpProto::Tcp as u8 {
        let h: *const TcpHdr = ptr_at(ctx, l4_off)?;
        let dp = u16::from_be((*h).dest);
        let sp = u16::from_be((*h).source);
        let c = (dp == 80 || sp == 80 || dp == 8080 || sp == 8080 || dp == 21 || dp == 23) as u8;
        Ok((sp, dp, c))
    } else if proto == IpProto::Udp as u8 {
        let h: *const UdpHdr = ptr_at(ctx, l4_off)?;
        let dp = u16::from_be((*h).dest);
        let sp = u16::from_be((*h).source);
        let c = (dp == 53 || sp == 53) as u8;
        Ok((sp, dp, c))
    } else {
        Ok((0, 0, 0))
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
