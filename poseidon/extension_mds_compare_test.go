package poseidon

import (
	"math/big"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type compareExtMDS struct{ X [12][2]frontend.Variable }

func TestExtensionMDSCoefficientGuards(t *testing.T) {
	t.Run("row bound", func(t *testing.T) {
		original := MDS_MATRIX_CIRC[0]
		defer func() { MDS_MATRIX_CIRC[0] = original }()
		MDS_MATRIX_CIRC[0] = uint64(265)
		defer func() {
			if recover() == nil {
				t.Fatal("accepted an oversized MDS coefficient")
			}
		}()
		validateExtensionMdsCoefficients()
	})
	t.Run("partial coefficient type", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("accepted a non-uint64 partial coefficient")
			}
		}()
		extensionMatrixCoefficient(-1)
	})
}

func (c *compareExtMDS) Define(api frontend.API) error {
	chip := NewGoldilocksChip(api)
	var x GoldilocksStateExtension
	for i := range x {
		x[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.X[i][0]), gl.NewVariable(c.X[i][1]))
		chip.gl.RangeCheckQE(x[i])
	}
	eq := func(a, b GoldilocksStateExtension) {
		for i := range a {
			api.AssertIsEqual(a[i][0].Limb, b[i][0].Limb)
			api.AssertIsEqual(a[i][1].Limb, b[i][1].Limb)
		}
	}
	eq(chip.MdsLayerExtension(x), chip.legacyMdsLayerExtension(x))
	eq(chip.MdsPartialLayerInitExtension(x), chip.legacyMdsPartialLayerInitExtension(x))
	for _, r := range []int{0, 11, 21} {
		eq(chip.MdsPartialLayerFastExtension(x, r), chip.legacyMdsPartialLayerFastExtension(x, r))
	}
	return nil
}

type extensionMDSRangeCircuit struct {
	X    [12][2]frontend.Variable
	Mode int `gnark:"-"`
}

func (c *extensionMDSRangeCircuit) Define(api frontend.API) error {
	chip := NewGoldilocksChip(api)
	var state GoldilocksStateExtension
	for i := range state {
		state[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.X[i][0]), gl.NewVariable(c.X[i][1]))
	}
	var result GoldilocksStateExtension
	switch c.Mode {
	case 0:
		result[0] = chip.MdsRowShfExtension(0, state)
	case 1:
		result = chip.MdsLayerExtension(state)
	case 2:
		result = chip.MdsPartialLayerInitExtension(state)
	case 3:
		result = chip.MdsPartialLayerFastExtension(state, 0)
	case 4:
		result = chip.MdsPartialLayerFastExtension(state, N_PARTIAL_ROUNDS-1)
	default:
		panic("invalid mode")
	}
	api.AssertIsEqual(result[0][0].Limb, 0)
	return nil
}

func TestExtensionMDSRejectsNoncanonicalInputs(t *testing.T) {
	for mode := 0; mode < 5; mode++ {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &extensionMDSRangeCircuit{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
			t.Fatal("unexpected commitment")
		}
		for invalid := -1; invalid < 24; invalid++ {
			a := extensionMDSRangeCircuit{Mode: mode}
			for i := range a.X {
				for j := range a.X[i] {
					a.X[i][j] = 0
				}
			}
			if invalid >= 0 {
				a.X[invalid/2][invalid%2] = gl.MODULUS
			}
			w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(w)
			if (err == nil) != (invalid == -1) {
				t.Fatalf("mode %d input %d: %v", mode, invalid, err)
			}
		}
	}
}
func TestExtensionMDSComparison(t *testing.T) {
	cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &compareExtMDS{})
	if e != nil {
		t.Fatal(e)
	}
	rng := rand.New(rand.NewSource(7))
	for k := 0; k < 20; k++ {
		var a compareExtMDS
		for i := range a.X {
			for j := range a.X[i] {
				switch k {
				case 0:
					a.X[i][j] = 0
				case 1:
					a.X[i][j] = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
				default:
					a.X[i][j] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
				}
			}
		}
		w, e := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if e = cs.IsSolved(w); e != nil {
			t.Fatalf("case %d: %v", k, e)
		}
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
}

func TestExtensionMDSGroth16(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &compareExtMDS{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	var assignment compareExtMDS
	for i := range assignment.X {
		assignment.X[i][0], assignment.X[i][1] = i+1, 2*i+3
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
}
