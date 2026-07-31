fn main() {
    // Add common library search paths for GmSSL
    println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");

    // When gmssl feature is enabled, verify GmSSL is installed
    #[cfg(feature = "gmssl")]
    {
        let gmssl = pkg_config::Config::new()
            .atleast_version("3.1.0")
            .probe("gmssl");

        match gmssl {
            Ok(lib) => {
                println!("cargo:rustc-cfg=has_gmssl");
                for path in &lib.link_paths {
                    println!("cargo:rustc-link-search=native={}", path.to_string_lossy());
                }
            }
            Err(e) => {
                // Emit a clear warning — fall back to pure Rust backend
                println!("cargo:warning=GmSSL 3.1+ not found via pkg-config: {}", e);
                println!(
                    "cargo:warning=SM9 will use the pure-Rust ark_bn254 backend (NOT GM/T 0044-2016 compliant)"
                );
                println!("cargo:warning=Install GmSSL: https://github.com/guanzhi/GmSSL");
                // Still links the system paths in case GmSSL is installed without pkg-config
                println!("cargo:rustc-link-lib=gmssl");
            }
        }
    }
}
