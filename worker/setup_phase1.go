package worker

import (
	"fmt"
	"math/bits"
	"time"

	"github.com/zilong-dai/gnark/backend/groth16/bn254/mpcsetup"
	groth16_bn254 "github.com/zilong-dai/gnark/backend/groth16/bn254"
	csbn254 "github.com/zilong-dai/gnark/constraint/bn254"
)

// SetupFromPtau reads a snarkjs Phase1 file and runs the local Phase2 setup.
func SetupFromPtau(r1cs *csbn254.R1CS, path string) (*groth16_bn254.ProvingKey, *groth16_bn254.VerifyingKey, error) {
	if r1cs == nil || r1cs.GetNbConstraints() < 2 {
		return nil, nil, fmt.Errorf("BN254 R1CS with at least two constraints is required")
	}
	power := uint(bits.Len(uint(r1cs.GetNbConstraints()-1)))
	fmt.Printf("[phase1] reading ptau: %s, domain power: %d\n", path, power)
	started := time.Now()
	phase1, err := ReadPhase1(path, power)
	if err != nil { return nil, nil, err }
	fmt.Printf("[phase1] read complete in %s\n", time.Since(started))
	return SetupFromPhase1(r1cs, phase1)
}

// SetupFromPhase1 derives a Groth16 proving and verifying key from a compiled
// BN254 R1CS and an already-decoded Phase1 transcript. The Phase1 points are
// consumed directly; file parsing and transcript provenance validation belong
// to the caller.
//
// This runs the fork's local Phase2 contribution to produce usable keys. It is
// an integration path, not a multi-party Phase2 ceremony.
func SetupFromPhase1(r1cs *csbn254.R1CS, phase1 *mpcsetup.Phase1) (*groth16_bn254.ProvingKey, *groth16_bn254.VerifyingKey, error) {
	if r1cs == nil {
		return nil, nil, fmt.Errorf("BN254 R1CS is required")
	}
	if phase1 == nil {
		return nil, nil, fmt.Errorf("Phase1 transcript is required")
	}
	if len(r1cs.GetCommitments().CommitmentIndexes()) != 0 {
		return nil, nil, fmt.Errorf("Phase1 setup does not support R1CS commitments")
	}
	n := len(phase1.Parameters.G1.AlphaTau)
	if n == 0 || n&(n-1) != 0 || n != 1<<bits.Len(uint(r1cs.GetNbConstraints()-1)) {
		return nil, nil, fmt.Errorf("Phase1 capacity %d must equal the R1CS domain size", n)
	}
	if len(phase1.Parameters.G1.Tau) == 0 ||
		len(phase1.Parameters.G1.AlphaTau) == 0 ||
		len(phase1.Parameters.G1.BetaTau) == 0 ||
		len(phase1.Parameters.G2.Tau) == 0 {
		return nil, nil, fmt.Errorf("Phase1 transcript has empty parameter sections")
	}
	if len(phase1.Parameters.G1.AlphaTau) < r1cs.GetNbConstraints() {
		return nil, nil, fmt.Errorf("Phase1 capacity %d is smaller than R1CS constraint count %d", len(phase1.Parameters.G1.AlphaTau), r1cs.GetNbConstraints())
	}
	if len(phase1.Parameters.G1.Tau) < 2*len(phase1.Parameters.G1.AlphaTau)-1 ||
		len(phase1.Parameters.G1.BetaTau) < len(phase1.Parameters.G1.AlphaTau) ||
		len(phase1.Parameters.G2.Tau) < len(phase1.Parameters.G1.AlphaTau) {
		return nil, nil, fmt.Errorf("Phase1 parameter sections have inconsistent capacities")
	}

	fmt.Printf("[phase2] initializing: constraints=%d, domain=%d\n", r1cs.GetNbConstraints(), n)
	initStarted := time.Now()
	done := make(chan struct{})
	var phase2 mpcsetup.Phase2
	var evaluations mpcsetup.Phase2Evaluations
	func() {
		defer close(done)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fmt.Printf("[phase2] initialization still running after %s\n", time.Since(initStarted))
				case <-done:
					return
				}
			}
		}()
		phase2, evaluations = mpcsetup.InitPhase2(r1cs, phase1)
	}()
	fmt.Printf("[phase2] initialization complete in %s\n", time.Since(initStarted))
	started := time.Now()
	fmt.Println("[phase2] contribution started")
	phase2.Contribute()
	fmt.Printf("[phase2] contribution complete in %s\n", time.Since(started))
	started = time.Now()
	fmt.Println("[phase2] extracting keys")
	pk, vk := mpcsetup.ExtractKeys(phase1, &phase2, &evaluations, r1cs.GetNbConstraints())
	fmt.Printf("[phase2] key extraction complete in %s\n", time.Since(started))
	return &pk, &vk, nil
}
