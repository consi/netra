use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bpf_src = manifest_dir.join("bpf").join("xdp_filter.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_obj = out_dir.join("xdp_filter.o");
    let bpf_rs = out_dir.join("bpf_bytes.rs");

    // Detect architecture-specific include path
    let arch_include = if cfg!(target_arch = "x86_64") {
        "/usr/include/x86_64-linux-gnu"
    } else if cfg!(target_arch = "aarch64") {
        "/usr/include/aarch64-linux-gnu"
    } else {
        "/usr/include"
    };

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            &format!("-I{arch_include}"),
            "-c",
            bpf_src.to_str().unwrap(),
            "-o",
            bpf_obj.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rerun-if-changed=bpf/xdp_filter.c");
            // Embed the compiled BPF object into the binary
            fs::write(
                &bpf_rs,
                "pub const BPF_BYTES: Option<&[u8]> = Some(include_bytes!(\"xdp_filter.o\"));\n",
            )
            .expect("failed to write bpf_bytes.rs");
        }
        Ok(s) => {
            eprintln!(
                "warning: clang failed to compile BPF program (exit {}), AF_XDP will not be available at runtime",
                s.code().unwrap_or(-1)
            );
            fs::write(&bpf_rs, "pub const BPF_BYTES: Option<&[u8]> = None;\n")
                .expect("failed to write bpf_bytes.rs");
        }
        Err(e) => {
            eprintln!(
                "warning: clang not found ({e}), BPF program not compiled, AF_XDP will not be available at runtime"
            );
            fs::write(&bpf_rs, "pub const BPF_BYTES: Option<&[u8]> = None;\n")
                .expect("failed to write bpf_bytes.rs");
        }
    }
}
