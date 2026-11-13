package goldilocks

import "github.com/consensys/gnark-crypto/field/goldilocks"

const D = 2

type QuadraticExtensionAlgebraVariable = [D]QuadraticExtensionVariable

func NewQuadraticExtensionAlgebraVariable(
	a QuadraticExtensionVariable,
	b QuadraticExtensionVariable,
) QuadraticExtensionAlgebraVariable {
	return QuadraticExtensionAlgebraVariable{a, b}
}

func (p QuadraticExtensionVariable) ToQuadraticExtensionAlgebra() QuadraticExtensionAlgebraVariable {
	return [D]QuadraticExtensionVariable{p, ZeroExtension()}
}

func ZeroExtensionAlgebra() QuadraticExtensionAlgebraVariable {
	return ZeroExtension().ToQuadraticExtensionAlgebra()
}

func OneExtensionAlgebra() QuadraticExtensionAlgebraVariable {
	return OneExtension().ToQuadraticExtensionAlgebra()
}

func (p *Chip) AddExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var sum QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		sum[i] = p.AddExtension(a[i], b[i])
	}
	return sum
}

func (p *Chip) SubExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var diff QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		diff[i] = p.SubExtension(a[i], b[i])
	}
	return diff
}

func (p *Chip) MulExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	// In the quadratic tower with W=7, the result is
	// (a0*b0 + W*a1*b1, a0*b1 + a1*b0). Each component of the first
	// coefficient is below 64p² and of the second below 16p² when all
	// inputs are canonical. An 80-bit quotient and canonical remainder
	// therefore suffice, including for an adversarial witness.
	if D != 2 || W != 7 || p.api.Compiler().FieldBitLen() < 145 {
		panic("extension algebra multiplication requires D=2, W=7 and a host field larger than 2^144")
	}
	for _, value := range a {
		p.RangeCheckQE(value)
	}
	for _, value := range b {
		p.RangeCheckQE(value)
	}
	ac := p.MulExtensionNoReduce(a[0], b[0])
	bd := p.MulExtensionNoReduce(a[1], b[1])
	ad := p.MulExtensionNoReduce(a[0], b[1])
	bc := p.MulExtensionNoReduce(a[1], b[0])
	var product QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		constant := p.AddNoReduce(ac[i], p.MulNoReduce(bd[i], NewVariable(W)))
		linear := p.AddNoReduce(ad[i], bc[i])
		product[0][i] = p.ReduceWithMaxBits(constant, 80)
		product[1][i] = p.ReduceWithMaxBits(linear, 80)
	}
	return product
}

func (p *Chip) ScalarMulExtensionAlgebra(
	a QuadraticExtensionVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var product QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		product[i] = p.MulExtension(a, b[i])
	}
	return product
}

func (p *Chip) PartialInterpolateExtAlgebra(
	domain []goldilocks.Element,
	values []QuadraticExtensionAlgebraVariable,
	barycentricWeights []goldilocks.Element,
	point QuadraticExtensionAlgebraVariable,
	initialEval QuadraticExtensionAlgebraVariable,
	initialPartialProd QuadraticExtensionAlgebraVariable,
) (QuadraticExtensionAlgebraVariable, QuadraticExtensionAlgebraVariable) {
	n := len(values)
	if n == 0 {
		panic("Cannot interpolate with no values")
	}
	if n != len(domain) {
		panic("Domain and values must have the same length")
	}
	if n != len(barycentricWeights) {
		panic("Domain and barycentric weights must have the same length")
	}

	newEval := initialEval
	newPartialProd := initialPartialProd
	for i := 0; i < n; i++ {
		val := values[i]
		x := domain[i]
		xField := NewVariable(x)
		xQE := xField.ToQuadraticExtension()
		xQEAlgebra := xQE.ToQuadraticExtensionAlgebra()
		weight := NewVariable(barycentricWeights[i].Uint64()).ToQuadraticExtension()
		term := p.SubExtensionAlgebra(point, xQEAlgebra)
		weightedVal := p.ScalarMulExtensionAlgebra(weight, val)
		newEval = p.MulExtensionAlgebra(newEval, term)
		tmp := p.MulExtensionAlgebra(weightedVal, newPartialProd)
		newEval = p.AddExtensionAlgebra(newEval, tmp)
		newPartialProd = p.MulExtensionAlgebra(newPartialProd, term)
	}

	return newEval, newPartialProd
}
