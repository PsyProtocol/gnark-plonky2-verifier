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
	inputMax := new(big.Int).Sub(new(big.Int).Mul(p, big.NewInt(2)), big.NewInt(2))
	cubicMax := new(big.Int).Exp(inputMax, big.NewInt(3), nil)
	q3 := new(big.Int).Div(new(big.Int).Set(cubicMax), p)
	canonicalMax := new(big.Int).Sub(p, big.NewInt(1))
	seventhMax := new(big.Int).Mul(inputMax, new(big.Int).Mul(canonicalMax, canonicalMax))
	q7 := new(big.Int).Div(new(big.Int).Set(seventhMax), p)
	if q3.BitLen() > 131 || q7.BitLen() > 129 {
		t.Fatalf("S-box quotient bounds: x^3=%d bits, x^7=%d bits", q3.BitLen(), q7.BitLen())
	}
	host := ecc.BN254.ScalarField()
	if cubicMax.Cmp(host) >= 0 || seventhMax.Cmp(host) >= 0 {
		t.Fatal("S-box integer products exceed the host field")
	}
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
