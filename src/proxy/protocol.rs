//! PROXY protocol header builders (v1 text + v2 binary), std only.
//!
//! See https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt.
//! Only the PROXY command (forward real client info) is emitted.

use std::net::{IpAddr, SocketAddr};

/// Build a PROXY protocol v1 header for a TCP connection.
///
/// Produces the text line:
/// `PROXY TCP4 <srcip> <dstip> <sport> <dport>\r\n`
/// (or `TCP6` for IPv6 addresses).
pub fn v1_header(src: &SocketAddr, dst: &SocketAddr) -> Vec<u8> {
    let (src, dst) = (unmap(src), unmap(dst));
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            format!("PROXY TCP4 {} {} {} {}\r\n", s, d, src.port(), dst.port()).into_bytes()
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            format!("PROXY TCP6 {} {} {} {}\r\n", s, d, src.port(), dst.port()).into_bytes()
        }
        _ => Vec::new(), // mismatched families — no header
    }
}

/// Dual-stack listeners report IPv4 peers as v6-mapped (`::ffff:a.b.c.d`).
/// The PROXY protocol spec says such addresses must be presented as plain
/// IPv4 (TCP4), so normalize before building headers.
fn unmap(addr: &SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => *addr,
        },
        IpAddr::V4(_) => *addr,
    }
}

/// PROXY protocol v2 12-byte signature.
const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// Version (2) + command (PROXY = 0x1) packed into the high/low nibble.
const V2_VER_CMD: u8 = 0x21;

/// v2 transport protocol + address family.
const V2_TCP4: u8 = 0x11; // AF_INET  + STREAM
const V2_TCP6: u8 = 0x21; // AF_INET6 + STREAM

/// Build a PROXY protocol v2 header for a TCP connection.
///
/// Layout: 12-byte signature, ver+cmd byte (0x21), transport byte,
/// u16 BE address-block length, then the address block
/// (src+dst IP, src+dst port — all in network byte order).
pub fn v2_header(src: &SocketAddr, dst: &SocketAddr) -> Vec<u8> {
    let (src, dst) = (unmap(src), unmap(dst));
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let len: u16 = 12; // 4+4+2+2
            let s = s.octets();
            let dd = d.octets();
            let sp = src.port().to_be_bytes();
            let dp = dst.port().to_be_bytes();
            let lb = len.to_be_bytes();
            let mut out = Vec::with_capacity(16 + 12);
            out.extend_from_slice(V2_SIG);
            out.push(V2_VER_CMD);
            out.push(V2_TCP4);
            out.extend_from_slice(&lb);
            out.extend_from_slice(&s);
            out.extend_from_slice(&dd);
            out.extend_from_slice(&sp);
            out.extend_from_slice(&dp);
            out
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len: u16 = 36; // 16+16+2+2
            let s = s.octets();
            let dd = d.octets();
            let sp = src.port().to_be_bytes();
            let dp = dst.port().to_be_bytes();
            let lb = len.to_be_bytes();
            let mut out = Vec::with_capacity(16 + 36);
            out.extend_from_slice(V2_SIG);
            out.push(V2_VER_CMD);
            out.push(V2_TCP6);
            out.extend_from_slice(&lb);
            out.extend_from_slice(&s);
            out.extend_from_slice(&dd);
            out.extend_from_slice(&sp);
            out.extend_from_slice(&dp);
            out
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- v1 ----

    #[test]
    fn v1_ipv4() {
        let src: SocketAddr = "203.0.113.7:52188".parse().unwrap();
        let dst: SocketAddr = "100.64.0.5:25565".parse().unwrap();
        let h = v1_header(&src, &dst);
        assert_eq!(
            std::str::from_utf8(&h).unwrap(),
            "PROXY TCP4 203.0.113.7 100.64.0.5 52188 25565\r\n"
        );
    }

    #[test]
    fn v1_ipv6() {
        let src: SocketAddr = "[2001:db8::1]:52188".parse().unwrap();
        let dst: SocketAddr = "[fd7a:115c:a1e0::5]:25565".parse().unwrap();
        let h = v1_header(&src, &dst);
        assert_eq!(
            std::str::from_utf8(&h).unwrap(),
            "PROXY TCP6 2001:db8::1 fd7a:115c:a1e0::5 52188 25565\r\n"
        );
    }

    #[test]
    fn v1_mixed_families_empty() {
        let src: SocketAddr = "203.0.113.7:52188".parse().unwrap();
        let dst: SocketAddr = "[fd7a::5]:25565".parse().unwrap();
        assert!(v1_header(&src, &dst).is_empty());
    }

    #[test]
    fn v1_v4_mapped_peer_emits_tcp4() {
        // Dual-stack listener reports IPv4 peers as ::ffff:a.b.c.d; the
        // header must present them as plain TCP4 (spec requirement).
        let src: SocketAddr = "[::ffff:203.0.113.7]:52188".parse().unwrap();
        let dst: SocketAddr = "[::ffff:100.64.0.5]:25565".parse().unwrap();
        assert_eq!(
            std::str::from_utf8(&v1_header(&src, &dst)).unwrap(),
            "PROXY TCP4 203.0.113.7 100.64.0.5 52188 25565\r\n"
        );
    }

    #[test]
    fn v2_v4_mapped_peer_emits_tcp4() {
        let src: SocketAddr = "[::ffff:203.0.113.7]:52188".parse().unwrap();
        let dst: SocketAddr = "[::ffff:100.64.0.5]:25565".parse().unwrap();
        let h = v2_header(&src, &dst);
        assert_eq!(h.len(), 28, "v4-mapped must use the 12-byte v4 block");
        assert_eq!(h[13], 0x11, "transport byte must be TCP4");
    }

    // ---- v2 ----

    #[test]
    fn v2_ipv4() {
        let src: SocketAddr = "203.0.113.7:52188".parse().unwrap();
        let dst: SocketAddr = "100.64.0.5:25565".parse().unwrap();
        let h = v2_header(&src, &dst);

        // 12 sig + 1 ver/cmd + 1 transport + 2 length + 12 payload = 28
        assert_eq!(h.len(), 28);
        assert_eq!(&h[0..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(h[12], 0x21); // version 2, PROXY command
        assert_eq!(h[13], 0x11); // TCP4
        assert_eq!(&h[14..16], &12u16.to_be_bytes()); // address block length

        // Payload: src_ip(4) dst_ip(4) src_port(2) dst_port(2)
        assert_eq!(&h[16..20], &[203, 0, 113, 7]);
        assert_eq!(&h[20..24], &[100, 64, 0, 5]);
        assert_eq!(&h[24..26], &52188u16.to_be_bytes());
        assert_eq!(&h[26..28], &25565u16.to_be_bytes());
    }

    #[test]
    fn v2_ipv6() {
        let src: SocketAddr = "[2001:db8::1]:52188".parse().unwrap();
        let dst: SocketAddr = "[fd7a:115c:a1e0::5]:25565".parse().unwrap();
        let h = v2_header(&src, &dst);

        // 16 header + 36 payload = 52
        assert_eq!(h.len(), 52);
        assert_eq!(&h[0..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x21); // TCP6
        assert_eq!(&h[14..16], &36u16.to_be_bytes());

        // src addr bytes (16) — 2001:0db8:... begins 0x20 0x01 0x0d 0xb8
        assert_eq!(&h[16..18], &[0x20, 0x01]);
        assert_eq!(&h[18..20], &[0x0d, 0xb8]);
        // dst addr starts at offset 32, ends at 48 — fd7a:...
        assert_eq!(&h[32..34], &[0xfd, 0x7a]);
        // src port at 48, dst port at 50
        assert_eq!(&h[48..50], &52188u16.to_be_bytes());
        assert_eq!(&h[50..52], &25565u16.to_be_bytes());
    }
}
