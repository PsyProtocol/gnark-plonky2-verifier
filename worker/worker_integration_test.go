package worker

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	csbn254 "github.com/zilong-dai/gnark/constraint/bn254"
)

// Opt-in replay of private artifacts. Keep stdout/stderr private: GenerateProof
// currently logs proof material. No captured inputs or keys belong in the repo.
func TestGenerateProofRecordedArtifacts(t *testing.T) {
	root := os.Getenv("GNARK_REAL_FIXTURES")
	if root == "" {
		t.Skip("set GNARK_REAL_FIXTURES to a private artifacts directory")
	}
	for _, tc := range []struct {
		name     string
		keystore string
	}{
		{name: "bridge", keystore: ""},
		{name: "deposit", keystore: "deposit_append"},
		{name: "withdrawal", keystore: "withdrawal_claim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(name string) string {
				data, err := os.ReadFile(filepath.Join(root, "ffi", tc.name+"-00", name+".json"))
				if err != nil {
					t.Fatal(err)
				}
				return string(data)
			}
			common := read("common_circuit_data")
			proofInput := read("proof_with_public_inputs")
			verifier := read("verifier_only_circuit_data")
			keystore := filepath.Join(root, "keystore", tc.keystore)
			if !CheckKeysExist(keystore) {
				t.Fatal("recorded proving parameters are missing")
			}
			Initialize(keystore)
			proveValid := func(label string) {
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				proof, vk := GenerateProof(common, proofInput, verifier, keystore)
				elapsed := time.Since(start)
				runtime.ReadMemStats(&after)
				if VerifyProof(proof, vk) != "true" {
					t.Fatal("recorded proof failed external verification")
				}
				t.Logf("resource label=%s elapsed_ms=%d allocated_bytes=%d heap_alloc_bytes=%d", label, elapsed.Milliseconds(), after.TotalAlloc-before.TotalAlloc, after.HeapAlloc)
			}
			proveValid("before_invalid")

			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(proofInput), &raw); err != nil {
				t.Fatal(err)
			}
			var publicInputs []uint64
			if err := json.Unmarshal(raw["public_inputs"], &publicInputs); err != nil {
				t.Fatal(err)
			}
			if len(publicInputs) == 0 || publicInputs[0] > 1 {
				t.Fatal("expected a recorded bit-encoded public input")
			}
			publicInputs[0] ^= 1
			var err error
			raw["public_inputs"], err = json.Marshal(publicInputs)
			if err != nil {
				t.Fatal(err)
			}
			invalid, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			var rejected any
			func() {
				defer func() { rejected = recover() }()
				GenerateProof(common, string(invalid), verifier, keystore)
			}()
			failure, ok := rejected.(error)
			var constraintError *csbn254.UnsatisfiedConstraintError
			if !ok || !errors.As(failure, &constraintError) {
				t.Fatal("modified public input was not rejected by the formal constraint solver")
			}
			// A rejected witness must not poison the cached circuit or proving key.
			proveValid("after_invalid")
		})
	}
}
