#[cfg(windows)]
extern crate winres;

#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("../build-tools/assets/logo.ico");
    res.set_manifest_file("app.manifest");
    res.compile().unwrap();
}

#[cfg(not(windows))]
fn main() {}
