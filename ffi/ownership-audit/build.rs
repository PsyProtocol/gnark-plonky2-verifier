use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    for name in ["FFI_AUDIT_SOURCE", "FFI_AUDIT_ARCHIVE", "FFI_AUDIT_MOCK"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=tracker.c");
    let source = PathBuf::from(env::var("FFI_AUDIT_SOURCE").unwrap());
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rustc-env=FFI_AUDIT_SOURCE={}", source.display());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // The five unchanged declarations match the generated Go C header.
    fs::write(out.join("bindings.rs"), r#"
#[repr(C)]
pub struct Groth16ProofWithVK { pub proof: *mut libc::c_char, pub vk: *mut libc::c_char }
extern "C" {
    pub fn GenerateGroth16Proof(a: *mut libc::c_char,b: *mut libc::c_char,c: *mut libc::c_char,d: *mut libc::c_char) -> *mut Groth16ProofWithVK;
    pub fn GenerateGroth16ProofFromJson(a: *mut libc::c_char,b: *mut libc::c_char,c: *mut libc::c_char,d: *mut libc::c_char) -> *mut Groth16ProofWithVK;
    pub fn VerifyGroth16Proof(a: *mut libc::c_char,b: *mut libc::c_char) -> *mut libc::c_char;
    pub fn Initialize(a: *mut libc::c_char);
    pub fn ExportSolidityVerifier(a: *mut libc::c_char) -> *mut libc::c_char;
}
"#).unwrap();
    let mock = env::var_os("FFI_AUDIT_MOCK").is_some();
    let mut cc = Command::new("cc");
    cc.args(["-std=c11", "-O2", "-c", "tracker.c", "-o"])
        .arg(out.join("tracker.o"));
    if mock {
        cc.arg("-DAUDIT_MOCK");
    }
    assert!(cc.status().unwrap().success());
    println!("cargo:rustc-link-arg={}", out.join("tracker.o").display());
    if !mock {
        let archive = env::var("FFI_AUDIT_ARCHIVE").unwrap();
        println!("cargo:rerun-if-changed={archive}");
        println!("cargo:rustc-link-arg={archive}");
    }
    for symbol in [
        "free",
        "GenerateGroth16Proof",
        "GenerateGroth16ProofFromJson",
        "VerifyGroth16Proof",
        "Initialize",
        "ExportSolidityVerifier",
    ] {
        println!("cargo:rustc-link-arg=-Wl,--wrap={symbol}");
    }
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=m");
}
