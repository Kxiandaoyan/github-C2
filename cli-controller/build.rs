#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
    </windowsSettings>
  </application>
</assembly>
"#);
    res.compile().unwrap();
}

#[cfg(not(windows))]
fn main() {}
