use super::*;

fn result(status: u32, proof: &str, verifier: &str, message: &str) -> DigestBitsResult {
    unsafe {
        let pointer = libc::calloc(1, std::mem::size_of::<bindings::Groth16DigestBitsResult>())
            as *mut bindings::Groth16DigestBitsResult;
        assert!(!pointer.is_null());
        let copy = |value: &str| {
            let value = CString::new(value).unwrap();
            let pointer = libc::strdup(value.as_ptr());
            assert!(!pointer.is_null());
            pointer
        };
        (*pointer).status = status;
        (*pointer).proof_json = copy(proof);
        (*pointer).verifier_json = copy(verifier);
        (*pointer).error_message = copy(message);
        DigestBitsResult(pointer)
    }
}

#[test]
fn copies_success_before_native_deallocation() {
    let proof = result(0, "{\"proof\":1}", "{\"verifier\":2}", "").into_proof(false).unwrap();
    assert_eq!(proof, DigestBitsProof {
        proof_json: "{\"proof\":1}".into(),
        verifier_json: "{\"verifier\":2}".into(),
    });
    assert_eq!(result(0, "", "", "").into_proof(true).unwrap(), DigestBitsProof {
        proof_json: String::new(), verifier_json: String::new(),
    });
}

#[test]
fn preserves_typed_native_failures() {
    for status in 1..=5 {
        assert_eq!(result(status, "", "", "failure").into_proof(false).unwrap_err(),
            DigestBitsError { status, message: "failure".into() });
    }
}

#[test]
fn rejects_broken_native_result_contract() {
    assert_eq!(DigestBitsResult(std::ptr::null_mut()).into_proof(false).unwrap_err().status, 5);
    for (status, proof, verifier, message, setup) in [
        (0, "", "", "", false),
        (0, "proof", "verifier", "", true),
        (0, "proof", "verifier", "error", false),
        (3, "proof", "", "error", false),
        (3, "", "", "", false),
        (6, "", "", "error", false),
    ] {
        assert_eq!(result(status, proof, verifier, message).into_proof(setup).unwrap_err().status, 5);
    }
    let missing = result(0, "proof", "verifier", "");
    unsafe {
        libc::free((*missing.0).proof_json.cast());
        (*missing.0).proof_json = std::ptr::null_mut();
    }
    assert_eq!(missing.into_proof(false).unwrap_err().status, 5);
    let invalid = result(0, "proof", "verifier", "");
    unsafe { *(*invalid.0).proof_json = 0xffu8 as libc::c_char; }
    assert_eq!(invalid.into_proof(false).unwrap_err().status, 5);
}

#[test]
fn rejects_nul_in_each_borrowed_input() {
    for artifact in [DigestArtifact::DepositAggregate, DigestArtifact::WithdrawalBatch, DigestArtifact::RewardBatch] {
        for (identity, proof, directory) in [
            ("\0", "{}", "unused"), ("{}", "\0", "unused"), ("{}", "{}", "\0"),
        ] {
            assert_eq!(generate_digest_bits_proof(artifact, identity, proof, directory).unwrap_err().status, 1);
        }
        assert_eq!(setup_digest_bits(artifact, "\0", "unused").unwrap_err().status, 1);
        assert_eq!(setup_digest_bits(artifact, "{}", "\0").unwrap_err().status, 1);
    }
}

#[test]
fn native_exports_return_typed_validation_failures() {
    for artifact in [DigestArtifact::DepositAggregate, DigestArtifact::WithdrawalBatch, DigestArtifact::RewardBatch] {
        for (identity, status) in [("{", 1), ("{}", 2)] {
            assert_eq!(generate_digest_bits_proof(artifact, identity, "{}", "unused").unwrap_err().status, status);
            assert_eq!(setup_digest_bits(artifact, identity, "unused").unwrap_err().status, status);
        }
    }
    unsafe {
        let result = bindings::GenerateGroth16DigestBitsProof(1, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(DigestBitsResult(result).into_proof(false).unwrap_err().status, 1);
        let result = bindings::SetupGroth16DigestBits(2, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(DigestBitsResult(result).into_proof(true).unwrap_err().status, 1);
        bindings::FreeGroth16DigestBitsResult(std::ptr::null_mut());
    }
}

#[test]
fn finalize_requests_reject_invalid_identity_before_setup() {
    assert_eq!(setup_finalize("{}", "unused").unwrap_err().status, 2);
    assert_eq!(generate_finalize_proof("{}", "{}", "unused").unwrap_err().status, 2);
    assert_eq!(setup_finalize("\0", "unused").unwrap_err().status, 1);
    assert_eq!(generate_finalize_proof("{}", "\0", "unused").unwrap_err().status, 1);
    assert_eq!(export_finalize_verifier("\0").unwrap_err().status, 1);
}
