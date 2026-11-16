package fri

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

func TestRadix2MaxCanonicalValues(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &weightCompareCircuit{Mode: 2, ArityBits: 4})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	for _, pattern := range []int{0, 1, 2} {
		c := assignment(7, max, max, [4]frontend.Variable{1, 0, 1, 1})
		for i := range c.Evals {
			for j := range c.Evals[i] {
				c.Evals[i][j] = max
				if pattern == 1 && (i+j)%2 == 0 {
					c.Evals[i][j] = 0
				} else if pattern == 2 && i != 15 {
					c.Evals[i][j] = 0
				}
			}
		}
		if err := solve(cs, c); err != nil {
			t.Fatalf("pattern %d: %v", pattern, err)
		}
	}
}

func TestRadix2ReductionBounds(t *testing.T) {
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	square := new(big.Int).Mul(max, max)
	for _, tc := range []struct{ products, bits int64 }{{8, 67}, {2, 65}} {
		bound := new(big.Int).Mul(square, big.NewInt(tc.products))
		bound.Add(bound, new(big.Int).Mul(max, big.NewInt(2)))
		quotient := new(big.Int).Quo(bound, gl.MODULUS)
		if quotient.BitLen() > int(tc.bits) {
			t.Fatalf("%d products: quotient needs %d bits", tc.products, quotient.BitLen())
		}
	}
	// The commitment path rounds both quotient bounds to 80 bits.
	constraintMax := new(big.Int).Lsh(new(big.Int).Set(gl.MODULUS), 80)
	constraintMax.Sub(constraintMax, big.NewInt(1))
	if constraintMax.Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("reduction equality may wrap in host field")
	}
	// A shifted difference is below 2p, its constant multiple below
	// 2p^2, and the following extension product below 16p^3 / 4p^3.
	for _, tc := range []struct{ products, bits int64 }{{16, 133}, {4, 131}} {
		cube := new(big.Int).Exp(gl.MODULUS, big.NewInt(3), nil)
		bound := new(big.Int).Mul(cube, big.NewInt(tc.products))
		bound.Add(bound, new(big.Int).Mul(gl.MODULUS, big.NewInt(2)))
		if q := new(big.Int).Quo(bound, gl.MODULUS); q.BitLen() > int(tc.bits) {
			t.Fatalf("lazy quotient needs %d bits", q.BitLen())
		}
	}
	constraintMax.Lsh(new(big.Int).Set(gl.MODULUS), 144)
	constraintMax.Sub(constraintMax, big.NewInt(1))
	if constraintMax.Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("lazy reduction equality may wrap in host field")
	}
}
