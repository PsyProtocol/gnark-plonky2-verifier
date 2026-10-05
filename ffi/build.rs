use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| anyhow::anyhow!("OUT_DIR is missing"))?);
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().expect("FFI crate has a repository parent");
    println!("cargo:rerun-if-changed={}", manifest_dir.join("build.rs").display());
    for path in [
        "go.mod", "go.sum", "benchmark.go", "challenger", "cmd", "fri",
        "goldilocks", "plonk", "plonk/gates", "poseidon", "sha256",
        "trusted_setup", "types", "variables", "verifier", "worker",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    for name in [
        "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "CC", "CGO_ENABLED",
        "LIBCLANG_PATH", "BINDGEN_EXTRA_CLANG_ARGS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    std::env::set_current_dir(root)?;
    gobuild::Build::new()
        .file(root.join("cmd/main.go"))
        .out_dir(&out_dir)
        .buildmode(gobuild::BuildMode::CArchive)
        .compile("g16verifier");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=g16verifier");

    bindgen::Builder::default()
        .header(out_dir.join("libg16verifier.h").to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}
