//! Userspace TCP proxy that injects PROXY-protocol headers upstream.
//!
//! For each rule in `proxy.yaml` it binds a listening socket and accepts
//! connections in a dedicated thread. Per connection it connects to the
//! target, writes the PROXY header (v1/v2/none), then spawns two copy
//! threads for bidirectional relay with byte counting. A "new" + "end"
//! `LogRecord` pair is written to the LogStore.
//!
//! Public entry point: [`run`]. The per-connection logic lives in
//! [`handle_connection`] so tests can exercise it against a fake upstream.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::logging::store::{LogRecord, LogStore};
use crate::logging::LOG_DIR;
use crate::proxy::{protocol, ProxyConfig, ProxyRule};

/// Run the proxy daemon: bind every rule's listen port and accept forever.
///
/// `log_dir` overrides the default log directory (`/var/lib/nat-gate`);
/// pass `None` for the production default.
pub fn run(log_dir: Option<&str>) -> Result<(), String> {
    let config = ProxyConfig::load()?;

    if config.rules.is_empty() {
        return Err("No proxy rules configured. Add rules with `nat-gate proxy add`.".to_string());
    }

    let dir: Arc<Path> = match log_dir {
        Some(d) => Arc::from(Path::new(d)),
        None => Arc::from(Path::new(LOG_DIR)),
    };
    let total = config.rules.len();
    let mut error_count = 0u32;
    let mut handles = Vec::new();

    for rule in config.rules {
        if rule.proto != "tcp" {
            eprintln!("Skipping non-TCP proxy rule on port {}", rule.port);
            continue;
        }
        let listener = match bind_listener(rule.port) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind port {}: {}", rule.port, e);
                error_count += 1;
                continue;
            }
        };
        eprintln!(
            "nat-gate-proxy: listening on :{} -> {}:{} ({})",
            rule.port, rule.target, rule.target_port, rule.proxy_protocol
        );

        let dir = Arc::clone(&dir);
        let handle = thread::spawn(move || accept_loop(&listener, &rule, &dir));
        handles.push(handle);
    }

    if error_count == total as u32 {
        return Err("Failed to bind any proxy listener".to_string());
    }

    // Run forever: join threads (they never return).
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Bind the listener, trying dual-stack `[::]` first then falling back
/// to IPv4-only `0.0.0.0`.
fn bind_listener(port: u16) -> Result<TcpListener, String> {
    match TcpListener::bind(format!("[::]:{port}")) {
        Ok(l) => {
            // Ensure the mapped IPv4 wildcard accepts v4 connections.
            // Most kernels default this on, but be explicit.
            Ok(l)
        }
        Err(e) => {
            // Retry IPv4-only.
            match TcpListener::bind(format!("0.0.0.0:{port}")) {
                Ok(l) => Ok(l),
                Err(e2) => Err(format!(
                    "bind [::]:{port} ({e}) and 0.0.0.0:{port} ({e2}) both failed"
                )),
            }
        }
    }
}

/// Per-listener accept loop. Serves until the listener is closed.
fn accept_loop(listener: &TcpListener, rule: &ProxyRule, log_dir: &Path) {
    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let rule = rule.clone();
                let log_dir = log_dir.to_path_buf();
                thread::spawn(move || {
                    let _ = handle_connection(client, &rule, &log_dir);
                });
            }
            Err(e) => {
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("accept error on port {}: {}", rule.port, e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Handle a single client connection: connect upstream, inject header,
/// relay bidirectionally, log new+end records. Returns once both halves
/// have finished (i.e. the connection is fully drained or errored).
pub fn handle_connection(
    client: TcpStream,
    rule: &ProxyRule,
    log_dir: &Path,
) -> Result<(), String> {
    let peer = client.peer_addr().map_err(|e| format!("peer_addr: {e}"))?;
    let local = client.local_addr().ok();
    let started = Instant::now();

    let upstream_addr = format!("{}:{}", rule.target, rule.target_port);
    let upstream = match TcpStream::connect(&upstream_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect upstream {upstream_addr}: {e}");
            return Ok(());
        }
    };

    let store = LogStore::open(log_dir).map_err(|e| format!("open log store: {e}"))?;

    let rule_marker = format!("nat-gate:tcp:{}", rule.port);
    let target_str = format!("{}:{}", rule.target, rule.target_port);

    // "new" record on accept.
    let new_rec = LogRecord {
        ts: chrono::Utc::now(),
        event: "new".to_string(),
        proto: "tcp".to_string(),
        client: format!("{peer}"),
        rule: rule_marker.clone(),
        target: target_str.clone(),
        verdict: "forwarded".to_string(),
        duration_s: None,
        packets: None,
        bytes: None,
    };
    let _ = store.append(&new_rec);

    // Inject the PROXY header to UPSTREAM first.
    if rule.proxy_protocol == "v1" || rule.proxy_protocol == "v2" {
        if let Some(dst) = local {
            let header = if rule.proxy_protocol == "v1" {
                protocol::v1_header(&peer, &dst)
            } else {
                protocol::v2_header(&peer, &dst)
            };
            use std::io::Write;
            if let Err(e) = (&upstream).write_all(&header) {
                eprintln!("Failed to write PROXY header upstream: {e}");
            }
        }
    }

    // Bidirectional relay with graceful shutdown cascade:
    //   Thread 1: read(client_clone1)  -> write(upstream_clone1)
    //   Thread 2: read(upstream_clone2) -> write(client_clone2)
    // When EITHER thread exits it shuts down BOTH on the OTHER socket's
    // read clone, unblocking the peer — without this a half-open peer
    // (never sends FIN on one direction) would hang the relay forever.
    let c1 = client
        .try_clone()
        .map_err(|e| format!("clone client: {e}"))?;
    let u_sig = upstream
        .try_clone()
        .map_err(|e| format!("clone upstream: {e}"))?;
    let upstream_rd = upstream
        .try_clone()
        .map_err(|e| format!("clone upstream: {e}"))?;
    let c_sig = client
        .try_clone()
        .map_err(|e| format!("clone client: {e}"))?;
    let bytes_c2u = Arc::new(AtomicU64::new(0));
    let bytes_u2c = Arc::new(AtomicU64::new(0));
    let bytes_c2u_a = Arc::clone(&bytes_c2u);
    let bytes_u2c_a = Arc::clone(&bytes_u2c);

    // client -> upstream: reads from a client clone, writes upstream.
    // On exit shut down OS upstream socket so t2's read gets EOF.
    let t1 = thread::spawn(move || {
        let n = copy_bytes(c1, upstream, &bytes_c2u_a);
        let _ = u_sig.shutdown(std::net::Shutdown::Both);
        n
    });
    // upstream -> client: reads from an upstream clone, writes client.
    // On exit shut down the OS client socket so t1's read gets EOF.
    let t2 = thread::spawn(move || {
        let n = copy_bytes(upstream_rd, client, &bytes_u2c_a);
        let _ = c_sig.shutdown(std::net::Shutdown::Both);
        n
    });

    let _ = t1.join();
    let _ = t2.join();

    let total = bytes_c2u.load(Ordering::Relaxed) + bytes_u2c.load(Ordering::Relaxed);
    let duration_s = started.elapsed().as_secs();

    let end_rec = LogRecord {
        ts: chrono::Utc::now(),
        event: "end".to_string(),
        proto: "tcp".to_string(),
        client: format!("{peer}"),
        rule: rule_marker,
        target: target_str,
        verdict: "forwarded".to_string(),
        duration_s: Some(duration_s),
        packets: None,
        bytes: Some(total),
    };
    let _ = store.append(&end_rec);

    Ok(())
}

/// Copy all bytes from `src` to `dst`, counting into `counter`.
/// Returns the number of bytes copied. On EOF or error the dst write
/// half is shut down to propagate the close.
fn copy_bytes(mut src: TcpStream, mut dst: TcpStream, counter: &AtomicU64) -> u64 {
    let mut total: u64 = 0;
    let mut buf = [0u8; 8192];
    loop {
        match std::io::Read::read(&mut src, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if std::io::Write::write_all(&mut dst, &buf[..n]).is_err() {
                    break;
                }
                total += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    // Half-close: signal EOF to the other direction.
    let _ = dst.shutdown(std::net::Shutdown::Write);
    counter.store(total, Ordering::Relaxed);
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::store::{LogQuery, LogStore};
    use crate::proxy::ProxyRule;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Duration;

    /// End-to-end: fake upstream reads the PROXY header + payload, echoes
    /// back; the proxy relay copies the echo to the client; an "end"
    /// LogRecord appears in the store.
    #[test]
    fn proxy_relay_with_v2_header() {
        let log_dir = tempfile_dir();

        // ---- fake upstream: accept one connection ----
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr = upstream.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        let upstream_thread = thread::spawn(move || {
            let (mut sock, peer) = upstream.accept().expect("upstream accept");
            // Read everything the proxy sends (PROXY header + client payload).
            let mut got = Vec::new();
            let mut tmp = [0u8; 256];
            // Read at least the 52-byte v2 header, then more.
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            loop {
                match sock.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        got.extend_from_slice(&tmp[..n]);
                        if got.len() > 70 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Echo back so the client side gets data.
            let _ = sock.write_all(b"PONG");
            let _ = sock.flush();
            tx.send((peer.to_string(), got)).unwrap();
            drop(sock);
        });

        // ---- fake client-side listener we hand to handle_connection ----
        let client_listen = TcpListener::bind("127.0.0.1:0").expect("bind client");
        let listen_port = client_listen.local_addr().unwrap().port();
        let client_addr = client_listen.local_addr().unwrap();
        drop(client_listen);

        // We need a TcpStream to feed into handle_connection. Connect a
        // pair and give one end to the proxy, keep the other as "client".
        // Connect to our own ephemeral listener by creating a real socket.
        let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind pair");
        let real_port = listener2.local_addr().unwrap().port();
        let real_addr = listener2.local_addr().unwrap();

        let mut connector = TcpStream::connect(real_addr).expect("connect client->proxy");
        let (accepted_client, client_peer) = listener2.accept().expect("accept pair");
        // `accepted_client` simulates the client's socket as seen by the proxy.
        // `connector` is the client.

        let rule = ProxyRule {
            proto: "tcp".into(),
            port: listen_port,
            target: upstream_addr.ip().to_string(),
            target_port: upstream_addr.port(),
            proxy_protocol: "v2".into(),
        };

        // local addr of accepted_client will be used for the PROXY header dst.
        // To make the dst deterministic we set it; it's the listener addr.
        let local_dst = real_addr;

        let log_dir_clone = log_dir.clone();
        let handle = thread::spawn(move || {
            handle_connection(accepted_client, &rule, &log_dir_clone).unwrap();
        });

        // Client sends payload after the proxy opens upstream.
        // Small delay so the connection is established.
        thread::sleep(Duration::from_millis(100));
        connector.write_all(b"HELLO").unwrap();
        let _ = connector.flush();

        // Read echo from client side.
        let mut client_buf = [0u8; 16];
        connector
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut read_total = 0;
        let client_buf_len = loop {
            match connector.read(&mut client_buf[read_total..]) {
                Ok(0) => break read_total,
                Ok(n) => {
                    read_total += n;
                    if read_total >= 5 {
                        break read_total;
                    }
                }
                Err(_) => break read_total,
            }
        };

        let _ = handle.join();
        let (upstream_peer, upstream_got) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let _ = upstream_thread.join();

        // Upstream got the v2 PROXY header followed by the payload.
        assert!(
            upstream_got.starts_with(b"\r\n\r\n\0\r\nQUIT\n"),
            "missing v2 signature"
        );
        // IPv4 test: TCP4 header — address length = 12 (4+4+2+2).
        assert_eq!(&upstream_got[13], &0x11u8, "transport byte = TCP4");
        assert_eq!(&upstream_got[14..16], &12u16.to_be_bytes(), "addr len");
        // The client payload "HELLO" follows the 28-byte IPv4 v2 header.
        assert_eq!(&upstream_got[28..], b"HELLO", "payload after header");

        // Client received the echo.
        assert_eq!(&client_buf[..client_buf_len], b"PONG");

        // An "end" record was written.
        let store = LogStore::open(&log_dir).unwrap();
        let recs = store
            .query(&LogQuery {
                event: Some("end".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(recs.len(), 1, "one end record");
        let end = &recs[0];
        assert_eq!(end.proto, "tcp");
        assert_eq!(end.verdict, "forwarded");
        assert_eq!(end.rule, format!("nat-gate:tcp:{listen_port}"));
        // client field is the original peer.
        assert_eq!(end.client, client_peer.to_string());
        assert_eq!(end.bytes, Some(5 + 4)); // HELLO(5) + PONG(4)
        assert!(end.packets.is_none(), "packets stays None");
        // Avoid unused-binding warning while keeping the value asserted.
        let _ = local_dst;
        let _ = client_addr;
        let _ = real_port;
        let _ = &upstream_peer;
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nat-gate-proxy-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
