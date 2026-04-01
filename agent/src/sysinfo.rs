pub fn collect_sysinfo() -> String {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let username = whoami::username();
    let os = whoami::distro();

    format!("Hostname: {}\nUser: {}\nOS: {}", hostname, username, os)
}
