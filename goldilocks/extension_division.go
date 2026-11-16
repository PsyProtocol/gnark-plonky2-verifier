package goldilocks

import (
	"fmt"
	"math/big"

	"github.com/zilong-dai/gnark/constraint/solver"
)

func init() { solver.RegisterHint(addDivExtensionHint) }

// AddDivExtensionCanonical returns acc+(a-b)/denominator. Every input
// coefficient must already be constrained to [0,p), as for MulExtension.
// A zero denominator is rejected even when a=b.
func (p *Chip) AddDivExtensionCanonical(a, b, denominator, acc QuadraticExtensionVariable) QuadraticExtensionVariable {
	if W != 7 || p.api.Compiler().FieldBitLen() < 145 {
		panic("extension division requires W=7 and a host field larger than 2^144")
	}
	p.api.AssertIsEqual(p.IsZero(denominator), 0)
	result, err := p.api.Compiler().NewHint(addDivExtensionHint, 2,
		a[0].Limb, a[1].Limb, b[0].Limb, b[1].Limb,
		denominator[0].Limb, denominator[1].Limb, acc[0].Limb, acc[1].Limb)
	if err != nil {
		panic(err)
	}
	out := NewQuadraticExtensionVariable(NewVariable(result[0]), NewVariable(result[1]))
	p.RangeCheckQE(out)
	var difference QuadraticExtensionVariable
	for i := range difference {
		difference[i] = NewVariable(p.api.Add(p.api.Sub(out[i].Limb, acc[i].Limb), MODULUS))
	}
	product := p.MulAddExtensionNoReduce(difference, denominator, b)
	// Each shifted difference is below 2p: c0 <16p²+p, c1 <4p²+p.
	// The 69/67-bit quotients align to 80 on the commitment path.
	p.AssertIsEqualExtension(NewQuadraticExtensionVariable(
		p.ReduceWithBound(product[0], 69),
		p.ReduceWithBound(product[1], 67)), a)
	return out
}

func addDivExtensionHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
	if len(in) != 8 || len(out) != 2 {
		return fmt.Errorf("extension division expects eight inputs and two outputs")
	}
	for _, value := range in {
		if value.Sign() < 0 || value.Cmp(MODULUS) >= 0 {
			return fmt.Errorf("noncanonical extension division input")
		}
	}
	d0, d1 := in[4], in[5]
	norm := new(big.Int).Mul(d0, d0)
	norm.Sub(norm, new(big.Int).Mul(big.NewInt(7), new(big.Int).Mul(d1, d1)))
	inverse := new(big.Int).ModInverse(norm, MODULUS)
	if inverse == nil {
		return fmt.Errorf("zero extension denominator")
	}
	n0 := new(big.Int).Sub(in[0], in[2])
	n1 := new(big.Int).Sub(in[1], in[3])
	real := new(big.Int).Mul(n0, d0)
	real.Sub(real, new(big.Int).Mul(big.NewInt(7), new(big.Int).Mul(n1, d1)))
	imag := new(big.Int).Sub(new(big.Int).Mul(n1, d0), new(big.Int).Mul(n0, d1))
	for i, value := range []*big.Int{real, imag} {
		out[i].Mod(new(big.Int).Add(new(big.Int).Mul(value, inverse), in[6+i]), MODULUS)
	}
	return nil
}
