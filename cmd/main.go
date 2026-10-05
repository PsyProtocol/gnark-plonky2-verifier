package main

/*
#include <stdlib.h> // Include C standard library, if necessary
#include <string.h>
#include <stdint.h>
typedef struct {
    uint32_t status;
    char* proof_json;
    char* verifier_json;
    char* error_message;
} Groth16DigestBitsResult;
typedef struct {
    char* proof;
    char* vk;
} Groth16ProofWithVK;
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkgroth16 "github.com/zilong-dai/gnark/backend/groth16"

	"github.com/cf/gnark-plonky2-verifier/worker"
)

type Groth16ProofWithVK struct {
	Proof string
	Vk    string
}

func newGroth16ProofWithVK(proof string, vk string) *C.Groth16ProofWithVK {
	cProofWithVk := (*C.Groth16ProofWithVK)(C.malloc(C.sizeof_Groth16ProofWithVK))
	cProofWithVk.proof = C.CString(proof)
	cProofWithVk.vk = C.CString(vk)
	return cProofWithVk
}

func newGroth16DigestBitsResult(status uint32, proof, verifier, message string) *C.Groth16DigestBitsResult {
	result := (*C.Groth16DigestBitsResult)(C.calloc(1, C.sizeof_Groth16DigestBitsResult))
	if result == nil {
		return nil
	}
	result.status = C.uint32_t(status)
	result.proof_json = C.CString(proof)
	result.verifier_json = C.CString(verifier)
	result.error_message = C.CString(message)
	return result
}

func digestBitsResult(operation func() (string, string, error)) (result *C.Groth16DigestBitsResult) {
	completed := false
	defer func() {
		recover()
		if !completed {
			result = newGroth16DigestBitsResult(5, "", "", "native DigestBits operation panicked")
		}
	}()
	proof, verifier, err := operation()
	if err != nil {
		status := uint32(5)
		var typed *worker.DigestBitsError
		if errors.As(err, &typed) && typed != nil && typed.Status >= 1 && typed.Status <= 5 {
			status = typed.Status
		}
		message := err.Error()
		if message == "" {
			message = "native DigestBits operation failed"
		}
		result = newGroth16DigestBitsResult(status, "", "", message)
		completed = true
		return result
	}
	result = newGroth16DigestBitsResult(0, proof, verifier, "")
	completed = true
	return result
}

//export GenerateGroth16DigestBitsProof
func GenerateGroth16DigestBitsProof(artifact C.uint32_t, identityJSON, proofJSON, artifactDir *C.char) *C.Groth16DigestBitsResult {
	return digestBitsResult(func() (string, string, error) {
		if identityJSON == nil || proofJSON == nil || artifactDir == nil {
			return "", "", &worker.DigestBitsError{Status: 1, Message: "null DigestBits request string"}
		}
		return worker.GenerateDigestBitsProof(uint32(artifact), C.GoString(identityJSON), C.GoString(proofJSON), C.GoString(artifactDir))
	})
}

//export SetupGroth16DigestBits
func SetupGroth16DigestBits(artifact C.uint32_t, identityJSON, artifactDir *C.char) *C.Groth16DigestBitsResult {
	return digestBitsResult(func() (string, string, error) {
		if identityJSON == nil || artifactDir == nil {
			return "", "", &worker.DigestBitsError{Status: 1, Message: "null DigestBits request string"}
		}
		return "", "", worker.SetupDigestBits(uint32(artifact), C.GoString(identityJSON), C.GoString(artifactDir))
	})
}

//export GenerateGroth16FinalizeProof
func GenerateGroth16FinalizeProof(identityJSON, proofJSON, artifactDir *C.char) *C.Groth16DigestBitsResult {
	return digestBitsResult(func() (string, string, error) {
		if identityJSON == nil || proofJSON == nil || artifactDir == nil { return "", "", &worker.DigestBitsError{Status: 1, Message: "null finalize request"} }
		return worker.GenerateFinalizeProof(C.GoString(identityJSON), C.GoString(proofJSON), C.GoString(artifactDir))
	})
}

//export SetupGroth16Finalize
func SetupGroth16Finalize(identityJSON, artifactDir *C.char) *C.Groth16DigestBitsResult {
	return digestBitsResult(func() (string, string, error) {
		if identityJSON == nil || artifactDir == nil { return "", "", &worker.DigestBitsError{Status: 1, Message: "null finalize request"} }
		return "", "", worker.SetupFinalize(C.GoString(identityJSON), C.GoString(artifactDir))
	})
}

//export ExportFinalizeVerifier
func ExportFinalizeVerifier(artifactDir *C.char) *C.char {
	if artifactDir == nil { return C.CString("error: null finalize directory") }
	code, err := worker.ExportFinalizeVerifier(C.GoString(artifactDir))
	if err != nil { return C.CString(fmt.Sprintf("error: %v", err)) }
	return C.CString(code)
}

//export ReadFinalizeSetupIdentity
func ReadFinalizeSetupIdentity(artifactDir *C.char) *C.char {
	if artifactDir == nil { return C.CString("error: null finalize directory") }
	identity, err := worker.ReadFinalizeSetupIdentity(C.GoString(artifactDir))
	if err != nil { return C.CString(fmt.Sprintf("error: %v", err)) }
	return C.CString(identity)
}

//export FreeGroth16DigestBitsResult
func FreeGroth16DigestBitsResult(result *C.Groth16DigestBitsResult) {
	if result == nil {
		return
	}
	C.free(unsafe.Pointer(result.proof_json))
	C.free(unsafe.Pointer(result.verifier_json))
	C.free(unsafe.Pointer(result.error_message))
	C.free(unsafe.Pointer(result))
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char, keystore_path *C.char) *C.Groth16ProofWithVK {
	defer func() {
		if r := recover(); r != nil {
			panic(fmt.Sprintf("GenerateGroth16Proof panic escaped recover: %v", r))
		}
	}()

	proofStr := ""
	vkStr := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				proofStr = fmt.Sprintf("error: %v", r)
				vkStr = ""
			}
		}()
		proofStr, vkStr = worker.GenerateProof(
			C.GoString(common_circuit_data),
			C.GoString(proof_with_public_inputs),
			C.GoString(verifier_only_circuit_data),
			C.GoString(keystore_path),
		)
	}()

	return newGroth16ProofWithVK(proofStr, vkStr)
}

//export GenerateGroth16ProofFromJson
func GenerateGroth16ProofFromJson(common_circuit_data_json *C.char, proof_with_public_inputs_json *C.char, verifier_only_circuit_data_json *C.char, keystore_path *C.char) *C.Groth16ProofWithVK {
	defer func() {
		if r := recover(); r != nil {
			panic(fmt.Sprintf("GenerateGroth16ProofFromJson panic escaped recover: %v", r))
		}
	}()

	proofStr := ""
	vkStr := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				proofStr = fmt.Sprintf("error: %v", r)
				vkStr = ""
			}
		}()
		proofStr, vkStr = worker.GenerateProof(
			C.GoString(common_circuit_data_json),
			C.GoString(proof_with_public_inputs_json),
			C.GoString(verifier_only_circuit_data_json),
			C.GoString(keystore_path),
		)
	}()

	return newGroth16ProofWithVK(proofStr, vkStr)
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) *C.char {
	return C.CString(worker.VerifyProof(C.GoString(proofString), C.GoString(vkString)))
}

//export Initialize
func Initialize(keyPath *C.char) {
	worker.Initialize(C.GoString(keyPath))
}

//export ExportSolidityVerifier
func ExportSolidityVerifier(keystorePath *C.char) *C.char {
	vk, err := worker.ReadVerifyingKey(ecc.BN254, C.GoString(keystorePath)+"/"+worker.VK_PATH)
	if err != nil {
		return C.CString(fmt.Sprintf("error: %v", err))
	}
	var buf bytes.Buffer
	if err := vk.(gnarkgroth16.VerifyingKey).ExportSolidity(&buf); err != nil {
		return C.CString(fmt.Sprintf("error: %v", err))
	}
	return C.CString(buf.String())
}

func main() {
	path := "/tmp/proof"

	common_circuit_data, _ := os.ReadFile(path + "/common_circuit_data.json")
	proof_with_public_inputs, _ := os.ReadFile(path + "/proof_with_public_inputs.json")
	verifier_only_circuit_data, _ := os.ReadFile(path + "/verifier_only_circuit_data.json")

	proof_city, vk_city := worker.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data), "/tmp/groth16-keystore/0/")
	fmt.Println("proof city", proof_city)
	fmt.Println("vk city", vk_city)
}
