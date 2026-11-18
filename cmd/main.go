package main

/*
#include <stdlib.h> // Include C standard library, if necessary
#include <string.h>
typedef struct {
    char* proof;
    char* vk;
} Groth16ProofWithVK;
*/
import "C"
import (
	"bytes"
	"fmt"
	"os"

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

//export GenerateGroth16ProofFromPhase1
func GenerateGroth16ProofFromPhase1(common, proof, verifier, keystore, phase1 *C.char) *C.Groth16ProofWithVK {
	var proofStr, vkStr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				proofStr = fmt.Sprintf("error: %v", r)
				vkStr = ""
			}
		}()
		proofStr, vkStr = worker.GenerateProofFromPhase1(C.GoString(common), C.GoString(proof), C.GoString(verifier), C.GoString(keystore), C.GoString(phase1))
	}()
	return newGroth16ProofWithVK(proofStr, vkStr)
}

//export SetupGroth16
func SetupGroth16(common, proof, verifier, keystore *C.char) (result *C.char) {
	defer func() { if r := recover(); r != nil { result = C.CString(fmt.Sprintf("error: %v", r)) } }()
	if err := worker.SetupJSON(C.GoString(common), C.GoString(proof), C.GoString(verifier), C.GoString(keystore)); err != nil { return C.CString(fmt.Sprintf("error: %v", err)) }
	return C.CString("")
}

//export SetupGroth16FromPhase1
func SetupGroth16FromPhase1(common, proof, verifier, keystore, phase1 *C.char) (result *C.char) {
	defer func() { if r := recover(); r != nil { result = C.CString(fmt.Sprintf("error: %v", r)) } }()
	if err := worker.SetupFromPhase1JSON(C.GoString(common), C.GoString(proof), C.GoString(verifier), C.GoString(keystore), C.GoString(phase1)); err != nil { return C.CString(fmt.Sprintf("error: %v", err)) }
	return C.CString("")
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
