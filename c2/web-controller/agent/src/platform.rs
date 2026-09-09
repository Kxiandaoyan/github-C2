#[cfg(unix)]
use std::ffi::CStr;

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg(unix)]
pub enum Distro {
    Ubuntu,
    CentOS,
    RHEL,
    Debian,
    Fedora,
    Arch,
    Alpine,      // common in containers
    Amazon,      // AWS Amazon Linux 1/2/2023
    Unknown,
}

#[cfg(unix)]
impl Distro {
    pub fn name(&self) -> &'static str {
        match self {
            Distro::Ubuntu  => "Ubuntu",
            Distro::CentOS  => "CentOS",
            Distro::RHEL    => "RHEL",
            Distro::Debian  => "Debian",
            Distro::Fedora  => "Fedora",
            Distro::Arch    => "Arch",
            Distro::Alpine  => "Alpine",
            Distro::Amazon  => "Amazon Linux",
            Distro::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
#[cfg(unix)]
pub struct PlatformInfo {
    pub distro: Distro,
    pub distro_version: String,
    pub is_root: bool,
    pub arch: String,
    pub kernel_version: String,
}

#[cfg(unix)]
impl PlatformInfo {
    pub fn display_os(&self) -> String {
        if self.distro_version.is_empty() {
            self.distro.name().to_string()
        } else {
            format!("{} {}", self.distro.name(), self.distro_version)
        }
    }

    pub fn privilege_label(&self) -> &'static str {
        if self.is_root { "root" } else { "user" }
    }
}

#[cfg(unix)]
pub fn detect() -> PlatformInfo {
    use std::sync::OnceLock;
    // Cache the distro/kernel/arch (read once from /etc/os-release + uname).
    // is_root is NOT cached since it can change across exec() escalation.
    static CACHED: OnceLock<(Distro, String, String, String)> = OnceLock::new();
    let (distro, distro_version, kernel_version, arch) = CACHED.get_or_init(|| {
        let d = detect_distro();
        let dv = detect_distro_version();
        let (kv, ar) = detect_kernel_and_arch();
        (d, dv, kv, ar)
    }).clone();

    let is_root = unsafe { libc::geteuid() == 0 };

    PlatformInfo {
        distro,
        distro_version,
        is_root,
        arch,
        kernel_version,
    }
}

#[cfg(unix)]
fn detect_distro() -> Distro {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(id) = line.strip_prefix("ID=") {
                let id = id.trim().trim_matches('"').to_lowercase();
                return match id.as_str() {
                    "ubuntu"              => Distro::Ubuntu,
                    "centos"              => Distro::CentOS,
                    "rhel" | "redhat"     => Distro::RHEL,
                    // AlmaLinux / Rocky Linux are 1:1 RHEL clones; use same persistence strategy
                    "almalinux" | "alma"  => Distro::RHEL,
                    "rocky" | "rocky-linux" => Distro::RHEL,
                    "ol" | "oraclelinux"  => Distro::RHEL,
                    "debian"              => Distro::Debian,
                    "fedora"              => Distro::Fedora,
                    "arch" | "archlinux"  => Distro::Arch,
                    "alpine"              => Distro::Alpine,
                    "amzn" | "amazon"     => Distro::Amazon,
                    _                     => Distro::Unknown,
                };
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/etc/redhat-release") {
        if content.contains("CentOS") {
            return Distro::CentOS;
        }
        if content.contains("Red Hat") {
            return Distro::RHEL;
        }
    }

    if std::path::Path::new("/etc/debian_version").exists() {
        return Distro::Debian;
    }

    Distro::Unknown
}

#[cfg(unix)]
fn detect_distro_version() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(ver) = line.strip_prefix("VERSION_ID=") {
                return ver.trim().trim_matches('"').to_string();
            }
        }
    }
    String::new()
}

#[cfg(unix)]
fn detect_kernel_and_arch() -> (String, String) {
    let mut uname_data: libc::utsname = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::uname(&mut uname_data) };

    if result == 0 {
        let release = unsafe {
            CStr::from_ptr(uname_data.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let machine = unsafe {
            CStr::from_ptr(uname_data.machine.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        (release, machine)
    } else {
        ("unknown".to_string(), std::env::consts::ARCH.to_string())
    }
}
