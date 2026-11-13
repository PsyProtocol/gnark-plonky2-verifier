package poseidon

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type canonicalSBoxCircuit struct{ In, Out frontend.Variable }

func (c *canonicalSBoxCircuit) Define(api frontend.API) error {
	chip := NewGoldilocksChip(api)
	x := gl.NewVariable(c.In)
	chip.gl.RangeCheck(x)
	out := chip.sBoxMonomialCanonical(x)
	api.AssertIsEqual(out.Limb, c.Out)
	return nil
}

func TestCanonicalSBoxBoundsAndRejection(t *testing.T) {
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	cube := new(big.Int).Exp(max, big.NewInt(3), nil)
	if new(big.Int).Div(new(big.Int).Set(cube), gl.MODULUS).BitLen() > 128 || cube.Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("canonical S-box exceeds quotient or host-field bound")
	}
	if new(big.Int).Lsh(new(big.Int).Set(gl.MODULUS), 128).Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("128-bit quotient may wrap the host field")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalSBoxCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	for _, x := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(max, big.NewInt(1)), max} {
		out := new(big.Int).Exp(x, big.NewInt(7), gl.MODULUS)
		w, err := frontend.NewWitness(&canonicalSBoxCircuit{In: x, Out: out}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("input %s: %v", x, err)
		}
	}
	for _, a := range []*canonicalSBoxCircuit{{In: gl.MODULUS, Out: 0}, {In: 1, Out: 2}} {
		w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if cs.IsSolved(w) == nil {
			t.Fatalf("accepted invalid witness %+v", a)
		}
	}
}
