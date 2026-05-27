fn main() {
    let macos = cfg!(target_os = "macos");
    let unix = cfg!(unix);
    let windows = cfg!(windows);

    let wayland = unix && !macos && !windows;

    println!("cargo::rustc-check-cfg=cfg(wayland_clipboard)");
    println!("cargo::rustc-check-cfg=cfg(macos_clipboard)");
    println!("cargo::rustc-check-cfg=cfg(windows_clipboard)");

    if wayland {
        println!("cargo::rustc-cfg=wayland_clipboard");
    }
    if macos {
        println!("cargo::rustc-cfg=macos_clipboard");
    }
    if windows {
        println!("cargo::rustc-cfg=windows_clipboard");
    }
}
