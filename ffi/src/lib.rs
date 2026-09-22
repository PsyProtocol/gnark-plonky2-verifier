use std::ffi::{CStr, CString};

mod bindings {
    #![allow(
        unused,
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        // Silence "128-bit integers don't currently have a known stable ABI" warnings
        improper_ctypes,
        // Silence "constants have by default a `'static` lifetime" clippy warnings
        clippy::redundant_static_lifetimes,
        // https://github.com/rust-lang/rust-bindgen/issues/1651
        deref_nullptr,
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// The Go exports synchronously copy input strings with C.GoString. They neither
// mutate nor retain the caller's C buffers. Keep Rust ownership across the call.
// Returned strings/structs are allocated with C.CString/C.malloc and must instead
// be released with C free, never CString::from_raw.
struct OwnedCProof(*mut bindings::Groth16ProofWithVK);

impl Drop for OwnedCProof {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                libc::free((*self.0).proof.cast());
                libc::free((*self.0).vk.cast());
                libc::free(self.0.cast());
            }
        }
    }
}

impl OwnedCProof {
    unsafe fn into_strings(self) -> (String, String) {
        assert!(!self.0.is_null(), "Go returned a null proof container");
        let proof = (*self.0).proof;
        let vk = (*self.0).vk;
        assert!(!proof.is_null() && !vk.is_null(), "Go returned a null proof string");
        (
            CStr::from_ptr(proof).to_string_lossy().into_owned(),
            CStr::from_ptr(vk).to_string_lossy().into_owned(),
        )
        // Drop also releases both buffers when conversion unwinds.
    }
}

struct OwnedCString(*mut std::os::raw::c_char);

impl Drop for OwnedCString {
    fn drop(&mut self) {
        unsafe { libc::free(self.0.cast()) }
    }
}

impl OwnedCString {
    unsafe fn into_string(self) -> String {
        assert!(!self.0.is_null(), "Go returned a null string");
        CStr::from_ptr(self.0).to_string_lossy().into_owned()
    }
}

pub fn generate_groth16_proof(
    common_circuit_data: &str,
    proof_with_public_inputs: &str,
    verifier_only_circuit_data: &str,
    keystore_path: &str,
) -> (String, String) {
    let c_common_circuit_data = CString::new(common_circuit_data).unwrap();
    let c_proof_with_public_inputs = CString::new(proof_with_public_inputs).unwrap();
    let c_verifier_only_circuit_data = CString::new(verifier_only_circuit_data).unwrap();
    let c_keystore_path = CString::new(keystore_path).unwrap();
    unsafe {
        let c_proof_with_vk = bindings::GenerateGroth16Proof(
            c_common_circuit_data.as_ptr().cast_mut(),
            c_proof_with_public_inputs.as_ptr().cast_mut(),
            c_verifier_only_circuit_data.as_ptr().cast_mut(),
            c_keystore_path.as_ptr().cast_mut(),
        );
        OwnedCProof(c_proof_with_vk).into_strings()
    }
}

/// JSON-aware version: accepts JSON strings directly without needing plonky2 Rust types.
/// This avoids serde on plonky2 types and goes straight through the Go FFI.
pub fn generate_groth16_proof_from_json(
    common_circuit_data_json: &str,
    proof_with_public_inputs_json: &str,
    verifier_only_circuit_data_json: &str,
    keystore_path: &str,
) -> (String, String) {
    let c_common = CString::new(common_circuit_data_json).unwrap();
    let c_proof = CString::new(proof_with_public_inputs_json).unwrap();
    let c_verifier = CString::new(verifier_only_circuit_data_json).unwrap();
    let c_keystore = CString::new(keystore_path).unwrap();
    unsafe {
        let c_proof_with_vk = bindings::GenerateGroth16ProofFromJson(
            c_common.as_ptr().cast_mut(),
            c_proof.as_ptr().cast_mut(),
            c_verifier.as_ptr().cast_mut(),
            c_keystore.as_ptr().cast_mut(),
        );
        OwnedCProof(c_proof_with_vk).into_strings()
    }
}

pub fn verify_groth16_proof(
    proof_string: &str,
    vk_string: &str,
) -> String {
    let c_proof_string = CString::new(proof_string).unwrap();
    let c_vk_string = CString::new(vk_string).unwrap();
    unsafe {
        let result = bindings::VerifyGroth16Proof(
            c_proof_string.as_ptr().cast_mut(),
            c_vk_string.as_ptr().cast_mut(),
        );
        OwnedCString(result).into_string()
    }
}

pub fn initialize(key_path: &str) {
    let c_key_path_string = CString::new(key_path).unwrap();
    unsafe {
        bindings::Initialize(c_key_path_string.as_ptr().cast_mut());
    }
}

pub fn export_solidity_verifier(keystore_path: &str) -> String {
    let c_keystore_path = CString::new(keystore_path).unwrap();
    unsafe {
        let c_result = bindings::ExportSolidityVerifier(c_keystore_path.as_ptr().cast_mut());
        OwnedCString(c_result).into_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_groth16_proof_test() {
        let path = "/tmp/plonky2_proof/0/";
        generate_groth16_proof(
            &std::fs::read_to_string(format!("{}{}", path, "common_circuit_data.json")).unwrap(),
            &std::fs::read_to_string(format!("{}{}", path, "proof_with_public_inputs.json")).unwrap(),
            &std::fs::read_to_string(format!("{}{}", path, "verifier_only_circuit_data.json")).unwrap(),
            "/tmp/groth16-keystore/0/"
        );
    }

    #[test]
    fn verify_groth16_proof_test() {
        assert_eq!(verify_groth16_proof(
            r#"{"Ar":{"X":"1329145699744998650582123539748758131981121814248135313648321078750287229596232401556925205479721400758797696888283","Y":"3459599132675101346980938962578890629946098551059473119459056925455527472091375891085834888631817909127562768014125"},"Krs":{"X":"3231668667724666957067737282328302929429324224789856778947126204004211744707209465320169499251368257777708556918973","Y":"470080714854961201119073719342128756886263786247785700659509286387758176724355020470508829221638845137172237802758"},"Bs":{"X":{"A0":"3222006944687408454447577451658299215465924170469828979595784206440152608707939031933931819723523664441371992520313","A1":"1929225390113390283153659441972926812895632359516235343468950390677339311245637705815887316489301579950449312327083"},"Y":{"A0":"3344375775814228737138851776165792993688011362642650155997379044613305260936051193434502999968635825279167158146834","A1":"3900126452604538853476087611009377421493964723194237626880608272609720641940987808230133617982645195616634760089400"}},"Commitments":[],"CommitmentPok":{"X":0,"Y":0}}"#,
            r#"{"CommitmentKey":"007ec97abb325e70f9186387fb634e7ba7e00356bc9a6f6124ed3fc3d15bb93381b5b134d8fd55ea5c128b0624e6946003a22c509bfc96e95e8de46b8d2a72ff47dcba9816383b2be9c24074cd2506438f32826cc9330b4b9196e26f036731a201d606d43dcd16556144942f210790b8c6446f69081783834ef702f8d52c797fe9fd6bfaeb3ffb580ba46bddf7131f9a05566993bb2f06af6fc0a1d096d1e120f84ef23d3a5cf73052fa53b3d9503e0b0777915dbe5baf6ce5f7f5092f41fb2309e5a8af0a16f71551c21bfe3050e4ded0fb05801cffe3e07ba4d6c3ed53797e064db99c4ee8f9d6ccf5d4a41857d6ee1146d7976c24065ae9cb36dcb1156d80e84cc144280c7d5a4fb8e066faac006286861bffc97834e6c4d3adef21dd2cdf16753603498ec283878f5f7c74b4646dfaec0f6e355865b5a85ba6ecd45267a8e4996aa89d1954eb8c1e4dc33cc3f6460db4ed88a3d36ae52b207a2e2dea7adf28927de9263b3e68bae6c7cca42f87c17731a536f9559c91152d538e35c8235a","PublicAndCommitmentCommitted":[],"alpha_g1":["06751e7f5de8c005d395723cb3e1b4b45c561a222c61b08f1f685131744ed961f7e6243177ddd380c4a0bab70bd25c73","058d8dda2d9a1e56ba0035d80c1a4c65b66954ab57a4355227954328f73d8909dce399782206a7031e301cdb89718e8c"],"beta_g2":[["0d9d6a1c456a1585ae4f36f39f30998b516b7e6094b723509c4f8a9f7735ac06e1d7a6e430774aa1acc6a00758ed084a","029ab9c16b47edf6e5c61b65584bf480fdb5e02641bcfc57a1a80667ef62bc19aeb0cd8b95ef439dce2323e269286539"],["0dd68ffd4fa993b37757483451d37748abeaecd1a5cf5038bd78167ae1832e0258a1252511fa54e051a9160857ae5dde","0b8cac26322058a43cfd5ef94d2120b6f23aeed8280f2539440c437fd2f15e36eda6b40428dbcfb157f30df002f4a316"]],"delta_g2":[["0a060168e1ff7487ad763b9150f1eafce8540414e3ba34138804b6a3391d641c2b4cf9283209e1753a6c9df3e4d701a2","0dab3f0d9a76ff0a5d237b3689db6b8c0203fbd92b0cb18feecf25dd565cf9d7aeed54f2cc1392108344f9897214dd57"],["1476595a0c82c417165925d2c33c9b6c2a59d209b3dbafc8d158f44fa4c3fbf7d6d1a3787fc045b2b3edcdc22c77e185","100d976293f5f236e160fe2b5a7177bc806123f675845416b725b7f9e1cb7fa9653c168e986d361e628778f75f8090eb"]],"gamma_abc_g1":[["05bafef7b33972046aba13ae281fc917bbda64b4d36b14b2275341c8a94bac022ba8e6372553c6318dffd407f6592be2","14ba788a3b794c1d864dbf3562796c55892900d47720a3c8f489eaabf38015c0d3e80610b86d280fe5b1759015d47488"],["03cf3812c7b2125eefc25e58b07ac7f60b74c7116ebdfd22557d73900cfce84217f8e9ad4a31d13d9e0c92fef7d8c810","120dfcc09851d616a105e6a838f5952d00f962ad95fae6f2035ec17e71e02137d28a9d8210056647e3cc51493b4e91fd"],["0819420574a08b2d695ebd7b876f2d85f09958faa1879c2c6b003ce70459579470c6903643d593a4dc613fa30d61d186","157ad3bc9d8cb5ccc92be269bfc53b081ff7cb188ba2f8ac5cafea457029be69310e0209002357e4e73bf275ecad6798"]],"gamma_g2":[["02f0d09818887c2a359678b971527509d52fa4f3acb38006c2fedac5cb10e0d3b07e62394e17712053b5e4607c27225c","19a944313e543976666dbf9c04b3796171fb8989034b4c830e92e5f9bb5986472d578ecb59e1c9c71b7f28807c6c7569"],["06e289502bd923ea87e6be5434290befc910d116afba0e72b9567bd4da9441e6ce6da71ed87b8901a9e430bea17edd2a","057a96c8acc19890e5311f8c1c35bace326079615f6b8653da925af6df231c9d47c74674cda609b9e164a9e691513b1e"]]}"#
        ), String::from("true"));
    }
}
