package gates

import (
	"math/big"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type algebraMDSComparison struct {
	Inputs [poseidon.SPONGE_WIDTH][gl.D][gl.D]frontend.Variable
}

type algebraMDSRangeCircuit struct {
	Inputs [poseidon.SPONGE_WIDTH][gl.D][gl.D]frontend.Variable
}

func (c *algebraMDSRangeCircuit) Define(api frontend.API) error {
	var state [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable
	for i := range state {
		for j := range state[i] {
			state[i][j] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Inputs[i][j][0]), gl.NewVariable(c.Inputs[i][j][1]))
		}
	}
	result := (&PoseidonMdsGate{}).mdsLayerAlgebra(state, api)
	api.AssertIsEqual(result[0][0][0].Limb, 0)
	return nil
}

func TestAlgebraMDSRejectsNoncanonicalInput(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &algebraMDSRangeCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	for invalid := -1; invalid < poseidon.SPONGE_WIDTH*gl.D*gl.D; invalid++ {
		var a algebraMDSRangeCircuit
		for i := range a.Inputs {
			for j := range a.Inputs[i] {
				for k := range a.Inputs[i][j] {
					a.Inputs[i][j][k] = 0
				}
			}
		}
		if invalid >= 0 {
			a.Inputs[invalid/(gl.D*gl.D)][(invalid/gl.D)%gl.D][invalid%gl.D] = gl.MODULUS
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w)
		if (err == nil) != (invalid == -1) {
			t.Fatalf("input %d: solve error %v", invalid, err)
		}
	}
}

func (c *algebraMDSComparison) Define(api frontend.API) error {
	var state [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable
	for i := range state {
		for j := range state[i] {
			state[i][j] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Inputs[i][j][0]), gl.NewVariable(c.Inputs[i][j][1]))
		}
	}
	gate := &PoseidonMdsGate{}
	result := gate.mdsLayerAlgebra(state, api)
	for i := range result {
		legacy := gate.legacyMdsRowShfAlgebra(uint64(i), state, api)
		for j := range legacy {
			for k := range legacy[j] {
				api.AssertIsEqual(result[i][j][k].Limb, legacy[j][k].Limb)
			}
		}
	}
	return nil
}

func TestAlgebraMDSMatchesLegacy(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &algebraMDSComparison{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	rng := rand.New(rand.NewSource(99))
	for sample := 0; sample < 12; sample++ {
		var a algebraMDSComparison
		for i := range a.Inputs {
			for j := range a.Inputs[i] {
				for k := range a.Inputs[i][j] {
					switch sample {
					case 0:
						a.Inputs[i][j][k] = 0
					case 1:
						a.Inputs[i][j][k] = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
					default:
						a.Inputs[i][j][k] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
					}
				}
			}
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
	}
}

func TestAlgebraMDSGroth16(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &algebraMDSComparison{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	var a algebraMDSComparison
	for i := range a.Inputs {
		for j := range a.Inputs[i] {
			for k := range a.Inputs[i][j] {
				a.Inputs[i][j][k] = 1 + i + j + k
			}
		}
	}
	w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
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

func (g *PoseidonMdsGate) legacyMdsRowShfAlgebra(
	r uint64,
	v [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable,
	api frontend.API,
) gl.QuadraticExtensionAlgebraVariable {
	glApi := gl.New(api)
	if r >= poseidon.SPONGE_WIDTH {
		panic("MDS row index out of range")
	}

	res := gl.ZeroExtensionAlgebra()
	for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
		coeff := gl.NewQuadraticExtensionVariable(gl.NewVariable(poseidon.MDS_MATRIX_CIRC[i]), gl.Zero())
		res = glApi.AddExtensionAlgebra(res, glApi.ScalarMulExtensionAlgebra(coeff, v[(i+r)%poseidon.SPONGE_WIDTH]))
	}

	coeff := gl.NewQuadraticExtensionVariable(gl.NewVariable(poseidon.MDS_MATRIX_DIAG[r]), gl.Zero())
	res = glApi.AddExtensionAlgebra(res, glApi.ScalarMulExtensionAlgebra(coeff, v[r]))

	return res
}
