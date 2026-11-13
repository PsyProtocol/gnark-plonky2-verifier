package verifier

import (
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type booleanHashCircuit struct{ Inputs [9]frontend.Variable }

func (c *booleanHashCircuit) Define(api frontend.API) error {
	chip := &VerifierChip{api: api, poseidonGlChip: poseidon.NewGoldilocksChip(api)}
	inputs := make([]gl.Variable, len(c.Inputs))
	for i := range inputs {
		inputs[i] = gl.NewVariable(c.Inputs[i])
	}
	checked := chip.booleanPublicInputsHash(inputs)
	legacy := chip.GetPublicInputsHash(inputs)
	for i := range checked {
		api.AssertIsEqual(checked[i].Limb, legacy[i].Limb)
	}
	return nil
}

func TestBooleanPublicInputsHash(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &booleanHashCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	for _, pattern := range []int{0, 1, 0x155, 0x1ff} {
		var assignment booleanHashCircuit
		for i := range assignment.Inputs {
			assignment.Inputs[i] = (pattern >> i) & 1
		}
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("pattern %d: %v", pattern, err)
		}
	}
	invalid := booleanHashCircuit{Inputs: [9]frontend.Variable{2, 0, 0, 0, 0, 0, 0, 0, 0}}
	w, err := frontend.NewWitness(&invalid, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(w); err == nil {
		t.Fatal("accepted non-boolean input")
	}
	valid := booleanHashCircuit{Inputs: [9]frontend.Variable{1, 0, 1, 0, 1, 0, 1, 0, 1}}
	w, err = frontend.NewWitness(&valid, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	public, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
}
