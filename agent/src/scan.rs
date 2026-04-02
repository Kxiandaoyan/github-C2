use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::time::Duration;

pub fn scan_port(host: &str, port: u16) -> bool {
    let addr = match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return false,
        },
        Err(_) => return false,
    };

    TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
}

pub fn scan_ports(host: &str, ports: &str) -> String {
    let mut results = Vec::new();
    let mut scanned = 0;

    for port in ports.split(',') {
        if let Ok(p) = port.trim().parse::<u16>() {
            scanned += 1;
            if scan_port(host, p) {
                results.push(format!("{}:{} open", host, p));
            }
        }
    }

    if results.is_empty() {
        format!("Scanned {} ports on {}, no open ports found", scanned, host)
    } else {
        format!("Scan results for {}:\n{}", host, results.join("\n"))
    }
}
