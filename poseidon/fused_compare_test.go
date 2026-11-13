package poseidon

import (
	"math/big"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type fusedComparison struct{ X [12]frontend.Variable }

func (c *fusedComparison) Define(api frontend.API) error {
	chip := NewGoldilocksChip(api)
	var input GoldilocksState
	for i := range input {
		input[i] = gl.NewVariable(c.X[i])
		chip.gl.RangeCheck(input[i])
	}
	current := chip.Poseidon(input)
	old := input
	rc := 0
	old = chip.refFullRounds(old, &rc)
	old = chip.refPartialRounds(old, &rc)
	old = chip.refFullRounds(old, &rc)
	for i := range old {
		api.AssertIsEqual(old[i].Limb, current[i].Limb)
	}
	return nil
}

func TestFusedPoseidonBounds(t *testing.T) {
	p := new(big.Int).Set(gl.MODULUS)
	inputMax := new(big.Int).Sub(new(big.Int).Mul(p, big.NewInt(265)), big.NewInt(1))
	cubicMax := new(big.Int).Exp(inputMax, big.NewInt(3), nil)
	q3 := new(big.Int).Div(new(big.Int).Set(cubicMax), p)
	canonicalMax := new(big.Int).Sub(p, big.NewInt(1))
	seventhMax := new(big.Int).Mul(inputMax, new(big.Int).Mul(canonicalMax, canonicalMax))
	q7 := new(big.Int).Div(new(big.Int).Set(seventhMax), p)
	if q3.BitLen() > 153 || q7.BitLen() > 137 {
		t.Fatalf("S-box quotient bounds: x^3=%d bits, x^7=%d bits", q3.BitLen(), q7.BitLen())
	}
	host := ecc.BN254.ScalarField()
	if cubicMax.Cmp(host) >= 0 || seventhMax.Cmp(host) >= 0 {
		t.Fatal("S-box integer products exceed the host field")
	}
	// Even the padded commitment-checker quotient must not wrap the host.
	paddedMax := new(big.Int).Mul(new(big.Int).Lsh(big.NewInt(1), 160), p)
	if paddedMax.Cmp(host) >= 0 {
		t.Fatal("padded S-box quotient can wrap the host field")
	}
	// The partial-round initial matrix combines 11 inputs below 265p
	// against uint64 coefficients; their quotient must fit in 80 bits.
	coefficientMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	initialMax := new(big.Int).Mul(inputMax, coefficientMax)
	initialMax.Mul(initialMax, big.NewInt(11))
	if new(big.Int).Div(new(big.Int).Set(initialMax), p).BitLen() > 80 || initialMax.Cmp(host) >= 0 {
		t.Fatal("partial-round initial matrix exceeds its bound")
	}
}

func TestLazyMdsCoefficientGuard(t *testing.T) {
	old := MDS_MATRIX_CIRC_VARS[0]
	defer func() { MDS_MATRIX_CIRC_VARS[0] = old }()
	MDS_MATRIX_CIRC_VARS[0] = uint64(265)
	defer func() {
		if recover() == nil {
			t.Fatal("accepted an MDS coefficient outside the lazy bound")
		}
	}()
	validateMdsCoefficients()
}
func TestFusedCompare(t *testing.T) {
	cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &fusedComparison{})
	if e != nil {
		t.Fatal(e)
	}
	rng := rand.New(rand.NewSource(37))
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	for k := 0; k < 40; k++ {
		var a fusedComparison
		for i := range a.X {
			switch k {
			case 0:
				a.X[i] = 0
			case 1:
				a.X[i] = max
			case 2:
				if i%2 == 0 {
					a.X[i] = max
				} else {
					a.X[i] = 0
				}
			default:
				a.X[i] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
			}
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(w); err != nil {
			t.Fatalf("case %d: %v", k, err)
		}
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
}
