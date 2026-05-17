// build.rs — compile the C wrappers and link against system zlib + brotli.
//
// "Honest error UX" (spec §4.6 / AC5): if pkg-config can't find the system
// packages, print a distro-aware install hint and exit non-zero BEFORE
// invoking cc. A bare linker dump is unacceptable for a first-time builder.

use std::process;

fn probe_or_die(pkg: &str, hint: &str) -> pkg_config::Library {
    match pkg_config::Config::new().probe(pkg) {
        Ok(lib) => lib,
        Err(e) => {
            eprintln!(
                "\nerror: libcompress-mojo: required system library `{}` not found via pkg-config.",
                pkg
            );
            eprintln!("       underlying pkg-config error: {}", e);
            eprintln!("{}", hint);
            process::exit(1);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src/last_error.c");
    println!("cargo:rerun-if-changed=src/zlib_wrapper.c");
    println!("cargo:rerun-if-changed=src/brotli_wrapper.c");
    println!("cargo:rerun-if-changed=build.rs");

    let zlib = probe_or_die(
        "zlib",
        "       install on Debian/Ubuntu : apt install zlib1g-dev pkg-config\n\
         \x20      install on Fedora/RHEL   : dnf install zlib-devel pkgconf\n\
         \x20      install on Alpine        : apk add zlib-dev pkgconf\n\
         \x20      install on Arch          : pacman -S zlib pkgconf\n\
         \x20      install on macOS         : brew install zlib pkg-config\n\
         \x20                                 (then export PKG_CONFIG_PATH=$(brew --prefix zlib)/lib/pkgconfig)",
    );

    let brotli = probe_or_die(
        "libbrotlidec",
        "       install on Debian/Ubuntu : apt install libbrotli-dev pkg-config\n\
         \x20      install on Fedora/RHEL   : dnf install brotli-devel pkgconf\n\
         \x20      install on Alpine        : apk add brotli-dev pkgconf\n\
         \x20      install on Arch          : pacman -S brotli pkgconf\n\
         \x20      install on macOS         : brew install brotli pkg-config",
    );

    let mut build = cc::Build::new();
    build.file("src/last_error.c");
    build.file("src/zlib_wrapper.c");
    build.file("src/brotli_wrapper.c");

    for inc in zlib.include_paths.iter().chain(brotli.include_paths.iter()) {
        build.include(inc);
    }

    // -fvisibility=default so the lcm_* symbols land in .dynsym of the
    // cdylib (Cargo defaults to hidden for staticlib but we're cdylib).
    build.flag_if_supported("-fvisibility=default");
    build.flag("-std=c11");
    build.warnings(true);
    build.extra_warnings(true);

    // Suppress cc's auto-emitted `cargo:rustc-link-lib=static=...` so we
    // can re-emit it with the +whole-archive modifier (needed for the
    // cdylib since no Rust code references the C symbols → --gc-sections
    // would strip them).
    build.cargo_metadata(false);
    build.compile("compress_wrappers");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static:+whole-archive=compress_wrappers");

    // Even after +whole-archive pulls the .o files in, rustc's cdylib
    // version script restricts .dynsym to Rust-declared #[no_mangle]
    // exports — `local:*;` hides every C symbol from the static
    // archive. Layering our own version script merges an extra global
    // clause so the lcm_* symbols stay visible for dlopen + dlsym.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo");
    println!(
        "cargo:rustc-link-arg-cdylib=-Wl,--version-script={}/lcm_export.ver",
        manifest_dir
    );
    println!("cargo:rerun-if-changed=lcm_export.ver");

    // pkg-config's auto-emit already covers -l/-L for zlib + brotli; keeping
    // the explicit forms documents the link inputs and is robust against any
    // future pkg-config-rs behaviour change.
    for lib in zlib.libs.iter().chain(brotli.libs.iter()) {
        println!("cargo:rustc-link-lib={}", lib);
    }
    for path in zlib.link_paths.iter().chain(brotli.link_paths.iter()) {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
}
