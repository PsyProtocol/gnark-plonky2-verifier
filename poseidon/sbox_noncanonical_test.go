package poseidon

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/constraint/solver"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

func TestSBoxAcceptsEquivalent64BitIntermediate(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalSBoxCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	exponent := new(big.Int).Div(new(big.Int).Sub(gl.MODULUS, big.NewInt(1)), big.NewInt(3))
	x := new(big.Int).Exp(big.NewInt(7), exponent, gl.MODULUS)
	if x.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("expected nontrivial cube root")
	}
	w, err := frontend.NewWitness(&canonicalSBoxCircuit{In: x, Out: new(big.Int).Exp(x, big.NewInt(7), gl.MODULUS)}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	modified := false
	hint := func(field *big.Int, in, out []*big.Int) error {
		if err := gl.ReduceHint(field, in, out); err != nil {
			return err
		}
		calls++
		if calls == 1 {
			if out[0].Sign() == 0 || out[1].Cmp(big.NewInt(1)) != 0 {
				t.Fatal("unexpected cubic reduction")
			}
			out[0].Sub(out[0], big.NewInt(1))
			out[1].Add(out[1], gl.MODULUS)
			modified = true
		}
		return nil
	}
	if err := cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(gl.ReduceHint), hint)); err != nil {
		t.Fatal(err)
	}
	if !modified {
		t.Fatal("did not exercise alternative intermediate")
	}
	bad := func(field *big.Int, in, out []*big.Int) error {
		if err := gl.ReduceHint(field, in, out); err != nil {
			return err
		}
		out[1].Set(new(big.Int).Lsh(big.NewInt(1), 64))
		return nil
	}
	if err := cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(gl.ReduceHint), bad)); err == nil {
		t.Fatal("accepted out-of-range remainder")
	}
}

func TestSBoxIntermediateBounds(t *testing.T) {
	p := gl.MODULUS
	r := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	for _, tc := range []struct {
		factor int64
		bits   int
	}{{1, 128}, {2, 129}, {265, 137}} {
		x := new(big.Int).Sub(new(big.Int).Mul(p, big.NewInt(tc.factor)), big.NewInt(1))
		product := new(big.Int).Mul(x, new(big.Int).Mul(r, r))
		if new(big.Int).Quo(new(big.Int).Set(product), p).BitLen() > tc.bits {
			t.Fatalf("factor %d: quotient too large", tc.factor)
		}
		if product.Cmp(ecc.BN254.ScalarField()) >= 0 {
			t.Fatal("product wraps host field")
		}
	}
}
