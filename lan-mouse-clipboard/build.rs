fn main() {
    let macos = cfg!(target_os = "macos");
    let unix = cfg!(unix);
    let x11 = cfg!(feature = "x11");

    let wayland = unix && !macos;
    let x11 = unix && !macos && x11;

    println!("cargo::rustc-check-cfg=cfg(wayland_clipboard)");
    println!("cargo::rustc-check-cfg=cfg(x11_clipboard)");
    println!("cargo::rustc-check-cfg=cfg(macos_clipboard)");

    if wayland {
        println!("cargo::rustc-cfg=wayland_clipboard");
    }
    if x11 {
        println!("cargo::rustc-cfg=x11_clipboard");
    }
    if macos {
        println!("cargo::rustc-cfg=macos_clipboard");
    }
}
