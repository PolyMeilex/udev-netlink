use std::{collections::HashMap, ffi::CStr, io::IoSliceMut, os::fd::RawFd};

use bytemuck::{Pod, Zeroable};
use memchr::memchr;
use nix::{
    libc,
    sys::{
        socket::{
            bind, recv, recvmsg, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag,
            SockProtocol, SockType,
        },
        stat::makedev,
    },
};

const UDEV_MONITOR_MAGIC: u32 = 0xfeedcafe;

#[repr(u32)]
enum UdevMonitorNetlinkGroup {
    None,
    Kernel,
    Udev = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable, PartialEq)]
struct MonitorNetlinkHeader {
    /// "libudev" prefix to distinguish libudev and kernel messages
    prefix: [libc::c_char; 8],
    /// Magic to protect against daemon <-> Library message format mismatch
    /// Used in the kernel from socket filter rules; needs to be stored in network order
    magic: libc::c_uint,
    /// Total length of header structure known to the sender
    header_size: libc::c_uint,
    /* Properties string buffer */
    properties_off: libc::c_uint,
    properties_len: libc::c_uint,
    /* Hashes of primary device properties strings, to let libudev subscribers
     * use in-kernel socket filters; values need to be stored in network order */
    filter_subsystem_hash: libc::c_uint,
    filter_devtype_hash: libc::c_uint,
    filter_tag_bloom_hi: libc::c_uint,
    filter_tag_bloom_lo: libc::c_uint,
}

fn main() {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkKObjectUEvent,
    )
    .unwrap();

    let addr = NetlinkAddr::new(
        nix::unistd::Pid::this().as_raw() as u32,
        UdevMonitorNetlinkGroup::Udev as u32,
    );

    new_filter(fd);

    bind(fd, &addr).unwrap();

    loop {
        let res = recv(fd, &mut [], MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC).unwrap();

        let mut buffer = vec![0u8; res];
        let mut iov = [IoSliceMut::new(&mut buffer)];

        let _res = recvmsg::<()>(fd, &mut iov, None, MsgFlags::empty()).unwrap();

        let tag = CStr::from_bytes_with_nul(&buffer[0..8]);

        let (offset, len) = if tag.ok().and_then(|v| v.to_str().ok()) == Some("libudev") {
            let header: MonitorNetlinkHeader = bytemuck::pod_read_unaligned(
                &buffer[..std::mem::size_of::<MonitorNetlinkHeader>()],
            );

            if header.magic != UDEV_MONITOR_MAGIC.to_be() {
                continue;
            }

            let offset = header.properties_off as usize;
            let len = header.properties_len as usize;

            (offset, len)
        } else {
            let id = memchr(0, &buffer).unwrap();
            let tag = CStr::from_bytes_with_nul(&buffer[0..=id]).unwrap();
            let tag = tag.to_string_lossy();

            let mut split = tag.split("@");

            let action = split.next().unwrap();
            let dev_path = split.next().unwrap();

            dbg!((action, dev_path));

            (id + 1, buffer.len())
        };

        let map = parse_map(&buffer[offset..len]);
        dbg!(&map);

        let major = map.get("MAJOR").and_then(|v| v.parse().ok());
        let minor = map.get("MINOR").and_then(|v| v.parse().ok());

        if let Some((major, minor)) = major.zip(minor) {
            let devnum = makedev(major, minor);
            dbg!(devnum);
        }
    }
}

fn parse_map(buffer: &[u8]) -> HashMap<String, String> {
    let mut i = 0;

    let mut map = HashMap::new();
    while i < buffer.len() {
        let props = &buffer[i..];

        let Some(id) = memchr(0, &props) else { break; };

        let prop = &props[..id + 1];
        i += prop.len();

        let prop = CStr::from_bytes_with_nul(prop).unwrap();

        let prop = prop.to_string_lossy();

        let mut sections = prop.trim().split("=");
        let key = sections.next().unwrap().to_string();
        let value = sections.next().unwrap().to_string();

        map.insert(key, value);
    }

    map
}

fn bpf_stmt(inss: &mut [libc::sock_filter], i: &mut usize, code: libc::c_uint, data: libc::c_uint) {
    let ins = &mut inss[*i];
    ins.code = code as u16;
    ins.k = data;
    *i += 1;
}

fn bpf_jmp(
    inss: &mut [libc::sock_filter],
    i: &mut usize,
    code: libc::c_uint,
    data: libc::c_uint,
    jt: libc::c_ushort,
    jf: libc::c_ushort,
) {
    let ins = &mut inss[*i];

    ins.code = code as u16;
    ins.jt = jt as u8;
    ins.jf = jf as u8;
    ins.k = data;
    *i += 1;
}

fn new_filter(fd: RawFd) {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};
    use memoffset::offset_of;

    let mut ins: [libc::sock_filter; 512] = unsafe { std::mem::zeroed() };
    let mut filter: libc::sock_fprog = unsafe { std::mem::zeroed() };
    let mut i = 0;

    let drm_hash = murmur2::murmur2("drm".as_bytes(), 0);
    let usb_hash = murmur2::murmur2("usb".as_bytes(), 0);

    // load magic in A
    bpf_stmt(
        &mut ins,
        &mut i,
        BPF_LD | BPF_W | BPF_ABS,
        offset_of!(MonitorNetlinkHeader, magic) as u32,
    );

    // jump if magic matches
    bpf_jmp(
        &mut ins,
        &mut i,
        BPF_JMP | BPF_JEQ | BPF_K,
        UDEV_MONITOR_MAGIC,
        1,
        0,
    );

    // wrong magic, pass packet
    bpf_stmt(&mut ins, &mut i, BPF_RET | BPF_K, 0x0);

    {
        // load device subsystem value in A
        bpf_stmt(
            &mut ins,
            &mut i,
            BPF_LD | BPF_W | BPF_ABS,
            offset_of!(MonitorNetlinkHeader, filter_subsystem_hash) as u32,
        );

        // jump if subsystem does not match
        bpf_jmp(&mut ins, &mut i, BPF_JMP | BPF_JEQ | BPF_K, usb_hash, 1, 0);

        bpf_stmt(&mut ins, &mut i, BPF_RET | BPF_K, 0x0);
    }

    /* matched, pass packet */
    bpf_stmt(&mut ins, &mut i, BPF_RET | BPF_K, u32::MAX);

    filter.len = i as u16;
    filter.filter = ins.as_mut_ptr();

    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &filter as *const _ as *const _,
            std::mem::size_of::<libc::sock_fprog>() as u32,
        )
    };

    println!("{}", nix::errno::Errno::from_i32(nix::errno::errno()));
    dbg!(res);
}
