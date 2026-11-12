package fri

import (
	"math/big"
	"math/bits"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/constraint"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type weightCompareCircuit struct {
	X, Beta0, Beta1 frontend.Variable
	Bits            [4]frontend.Variable
	Evals           [16][2]frontend.Variable
	Mode            int    `gnark:"-"`
	ArityBits       uint64 `gnark:"-"`
}

func (c *weightCompareCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	g.RangeCheck(gl.NewVariable(c.X))
	g.RangeCheck(gl.NewVariable(c.Beta0))
	g.RangeCheck(gl.NewVariable(c.Beta1))
	for _, bit := range c.Bits {
		api.AssertIsBoolean(bit)
	}
	evals := make([]gl.QuadraticExtensionVariable, 16)
	for i := range evals {
		evals[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Evals[i][0]), gl.NewVariable(c.Evals[i][1]))
		g.RangeCheckQE(evals[i])
	}
	beta := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Beta0), gl.NewVariable(c.Beta1))
	f := &Chip{api: api, gl: g}
	bits := c.Bits[:c.ArityBits]
	evals = evals[:1<<c.ArityBits]
	if c.Mode == 0 {
		f.computeEvaluationLegacy(gl.NewVariable(c.X), bits, c.ArityBits, evals, beta)
		return nil
	}
	if c.Mode == 1 {
		f.computeEvaluation(gl.NewVariable(c.X), bits, c.ArityBits, evals, beta)
		return nil
	}
	a := f.computeEvaluationLegacy(gl.NewVariable(c.X), bits, c.ArityBits, evals, beta)
	b := f.computeEvaluation(gl.NewVariable(c.X), bits, c.ArityBits, evals, beta)
	g.AssertIsEqualExtension(a, b)
	return nil
}
func assignment(x, b0, b1 frontend.Variable, bits [4]frontend.Variable) *weightCompareCircuit {
	c := &weightCompareCircuit{X: x, Beta0: b0, Beta1: b1, Bits: bits}
	for i := range c.Evals {
		c.Evals[i][0] = i + 1
		c.Evals[i][1] = i*17 + 2
	}
	return c
}
func solve(cs constraint.ConstraintSystem, c *weightCompareCircuit) error {
	w, e := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if e != nil {
		return e
	}
	return cs.IsSolved(w)
}
func TestDirectWeightsMatchLegacy(t *testing.T) {
	systems := make([]constraint.ConstraintSystem, 3)
	for mode := range systems {
		cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &weightCompareCircuit{Mode: mode, ArityBits: 4})
		if e != nil {
			t.Fatal(e)
		}
		systems[mode] = cs
	}
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	cases := []*weightCompareCircuit{assignment(1, 3, 2, [4]frontend.Variable{0, 0, 0, 0}), assignment(max, 6, 3, [4]frontend.Variable{1, 0, 1, 1}), assignment(7, max, 1, [4]frontend.Variable{1, 1, 1, 1})}
	for i, c := range cases {
		if e := solve(systems[2], c); e != nil {
			t.Errorf("valid case %d: %v", i, e)
		}
	}

	rng := rand.New(rand.NewSource(43))
	for mask := 0; mask < 16; mask++ {
		bits := [4]frontend.Variable{}
		for i := range bits {
			bits[i] = (mask >> i) & 1
		}
		for j := 0; j < 2; j++ {
			x := new(big.Int).SetUint64(rng.Uint64())
			x.Mod(x, gl.MODULUS)
			if x.Sign() == 0 {
				x.SetInt64(1)
			}
			c := assignment(x, new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS), 1, bits)
			for i := range c.Evals {
				for j := range c.Evals[i] {
					c.Evals[i][j] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
				}
			}
			if e := solve(systems[2], c); e != nil {
				t.Errorf("random mask=%d iteration=%d: %v", mask, j, e)
			}
		}
	}
	root := gl.PrimitiveRootOfUnity(4)
	g5 := goldilocks.NewElement(0)
	g5.Exp(root, big.NewInt(5))
	rejected := []*weightCompareCircuit{assignment(0, 3, 2, [4]frontend.Variable{0, 0, 0, 0}), assignment(1, 1, 0, [4]frontend.Variable{0, 0, 0, 0}), assignment(1, g5.Uint64(), 0, [4]frontend.Variable{0, 0, 0, 0})}
	for i, c := range rejected {
		for mode := 0; mode < 2; mode++ {
			if e := solve(systems[mode], c); e == nil {
				t.Errorf("mode %d accepted degenerate case %d", mode, i)
			}
		}
	}
}

func TestDirectWeightsSmallerArities(t *testing.T) {
	for arityBits := uint64(1); arityBits <= 3; arityBits++ {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &weightCompareCircuit{Mode: 2, ArityBits: arityBits})
		if err != nil {
			t.Fatal(err)
		}
		for mask := 0; mask < 1<<arityBits; mask++ {
			bits := [4]frontend.Variable{0, 0, 0, 0}
			for i := uint64(0); i < arityBits; i++ {
				bits[i] = (mask >> i) & 1
			}
			if err := solve(ccs, assignment(7, 12, 2, bits)); err != nil {
				t.Errorf("arityBits=%d mask=%d: %v", arityBits, mask, err)
			}
		}
	}
}

type singlePointCircuit struct{ X, Beta0, Beta1, Eval0, Eval1 frontend.Variable }

func (c *singlePointCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	eval := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Eval0), gl.NewVariable(c.Eval1))
	beta := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Beta0), gl.NewVariable(c.Beta1))
	g.RangeCheck(gl.NewVariable(c.X))
	g.RangeCheckQE(eval)
	g.RangeCheckQE(beta)
	f := &Chip{api: api, gl: g}
	a := f.computeEvaluationLegacy(gl.NewVariable(c.X), nil, 0, []gl.QuadraticExtensionVariable{eval}, beta)
	b := f.computeEvaluation(gl.NewVariable(c.X), nil, 0, []gl.QuadraticExtensionVariable{eval}, beta)
	g.AssertIsEqualExtension(a, b)
	return nil
}
func TestDirectWeightsSinglePointZeroCoset(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &singlePointCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	w, e := frontend.NewWitness(&singlePointCircuit{X: 0, Beta0: 1, Beta1: 1, Eval0: 2, Eval1: 3}, ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	if e = ccs.IsSolved(w); e != nil {
		t.Fatal(e)
	}
}
func TestDirectWeightsGroth16(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &weightCompareCircuit{Mode: 2, ArityBits: 4})
	if e != nil {
		t.Fatal(e)
	}
	witness, e := frontend.NewWitness(assignment(7, 12, 2, [4]frontend.Variable{1, 0, 1, 1}), ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	pk, vk, e := groth16.Setup(ccs)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := groth16.Prove(ccs, pk, witness)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := witness.Public()
	if e != nil {
		t.Fatal(e)
	}
	if e = groth16.Verify(proof, vk, pub); e != nil {
		t.Fatal(e)
	}
	if len(ccs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
}

// computeEvaluationLegacy preserves the previous algorithm solely for differential tests.
func (f *Chip) computeEvaluationLegacy(
	x gl.Variable,
	xIndexWithinCosetBits []frontend.Variable,
	arityBits uint64,
	evals []gl.QuadraticExtensionVariable,
	beta gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	arity := 1 << arityBits
	if (len(evals)) != arity {
		panic("len(evals) != arity")
	}
	if arityBits > 8 {
		panic("currently assuming that arityBits is <= 8")
	}

	g := gl.PrimitiveRootOfUnity(arityBits)
	gInv := goldilocks.NewElement(0)
	gInv.Exp(g, big.NewInt(int64(arity-1)))

	// The evaluation vector needs to be reordered first.  Permute the evals array such that each
	// element's new index is the bit reverse of it's original index.
	// OPTIMIZE - Since the size of the evals array should be constant (e.g. 2^arityBits),
	//        we can just hard code the permutation.
	permutedEvals := make([]gl.QuadraticExtensionVariable, len(evals))
	for i := uint8(0); i <= uint8(len(evals)-1); i++ {
		newIndex := bits.Reverse8(i) >> (8 - arityBits)
		permutedEvals[newIndex] = evals[i]
	}

	// Want `g^(arity - rev_x_index_within_coset)` as in the out-of-circuit version. Compute it
	// as `(g^-1)^rev_x_index_within_coset`.
	revXIndexWithinCosetBits := make([]frontend.Variable, len(xIndexWithinCosetBits))
	for i := 0; i < len(xIndexWithinCosetBits); i++ {
		revXIndexWithinCosetBits[len(xIndexWithinCosetBits)-1-i] = xIndexWithinCosetBits[i]
	}
	start := f.expFromBitsConstBase(gInv, revXIndexWithinCosetBits)
	cosetStart := f.gl.Mul(start, x)

	xPoints := make([]gl.QuadraticExtensionVariable, len(evals))
	yPoints := permutedEvals

	// OPTIMIZE: Make g_F a constant
	g_F := gl.NewVariable(g.Uint64()).ToQuadraticExtension()
	xPoints[0] = gl.QuadraticExtensionVariable{cosetStart, gl.Zero()}
	for i := 1; i < len(evals); i++ {
		xPoints[i] = f.gl.MulExtension(xPoints[i-1], g_F)
	}

	// OPTIMIZE:  This is n^2.  Is there a way to do this better?
	// Compute the barycentric weights
	barycentricWeights := make([]gl.QuadraticExtensionVariable, len(xPoints))
	for i := 0; i < len(xPoints); i++ {
		barycentricWeights[i] = gl.OneExtension()
		for j := 0; j < len(xPoints); j++ {
			if i != j {
				barycentricWeights[i] = f.gl.SubMulExtension(
					xPoints[i],
					xPoints[j],
					barycentricWeights[i],
				)
			}
		}
		// Take the inverse of the barycentric weights
		// OPTIMIZE: Can provide a witness to this value
		inv, hasInv := f.gl.InverseExtension(barycentricWeights[i])
		f.api.AssertIsEqual(hasInv, frontend.Variable(1))
		barycentricWeights[i] = inv
	}

	return f.interpolateLegacy(beta, xPoints, yPoints, barycentricWeights)
}

func (f *Chip) interpolateLegacy(
	x gl.QuadraticExtensionVariable,
	xPoints []gl.QuadraticExtensionVariable,
	yPoints []gl.QuadraticExtensionVariable,
	barycentricWeights []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	if len(xPoints) != len(yPoints) || len(xPoints) != len(barycentricWeights) {
		panic("length of xPoints, yPoints, and barycentricWeights are inconsistent")
	}

	lX := gl.OneExtension()
	for i := 0; i < len(xPoints); i++ {
		lX = f.gl.SubMulExtension(x, xPoints[i], lX)
	}

	sum := gl.ZeroExtension()

	lookupFromPoints := frontend.Variable(1)
	for i := 0; i < len(xPoints); i++ {
		quotient, hasQuotient := f.gl.DivExtension(
			barycentricWeights[i],
			f.gl.SubExtension(
				x,
				xPoints[i],
			),
		)

		lookupFromPoints = f.api.Mul(hasQuotient, lookupFromPoints)

		sum = f.gl.AddExtension(
			f.gl.MulExtension(
				yPoints[i],
				quotient,
			),
			sum,
		)
	}

	interpolation := f.gl.MulExtension(lX, sum)

	lookupVal := gl.ZeroExtension()
	// Now check if x is already within the xPoints
	for i := 0; i < len(xPoints); i++ {
		lookupVal = f.gl.Lookup(
			f.gl.IsZero(f.gl.SubExtension(x, xPoints[i])),
			lookupVal,
			yPoints[i],
		)
	}

	return f.gl.Lookup(lookupFromPoints, lookupVal, interpolation)
}

type interpolationUntrustedValueCircuit struct{ Y frontend.Variable }

func (c *interpolationUntrustedValueCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	f := &Chip{api: api, gl: g}
	evals := make([]gl.QuadraticExtensionVariable, 16)
	for i := range evals {
		evals[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Y), gl.Zero())
	}
	bits := []frontend.Variable{0, 0, 0, 0}
	beta := gl.NewQuadraticExtensionVariable(gl.NewVariable(3), gl.NewVariable(2))
	f.computeEvaluation(gl.NewVariable(7), bits, 4, evals, beta)
	return nil
}
func TestInterpolationRejectsNoncanonicalProofValues(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &interpolationUntrustedValueCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		v     frontend.Variable
		valid bool
	}{{0, true}, {new(big.Int).Sub(gl.MODULUS, big.NewInt(1)), true}, {gl.MODULUS, false}, {new(big.Int).Add(gl.MODULUS, big.NewInt(1)), false}} {
		w, e := frontend.NewWitness(&interpolationUntrustedValueCircuit{Y: tc.v}, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		e = ccs.IsSolved(w)
		if (e == nil) != tc.valid {
			t.Errorf("value=%v valid=%v err=%v", tc.v, tc.valid, e)
		}
	}
}

type interpolationPolynomialCircuit struct {
	Beta0, Beta1, Expected0, Expected1 frontend.Variable
	Evals                              [16]frontend.Variable
}

func (c *interpolationPolynomialCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	f := &Chip{api: api, gl: g}
	evals := make([]gl.QuadraticExtensionVariable, 16)
	for i := range evals {
		evals[i] = gl.NewVariable(c.Evals[i]).ToQuadraticExtension()
	}
	beta := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Beta0), gl.NewVariable(c.Beta1))
	g.RangeCheckQE(beta)
	out := f.computeEvaluation(gl.One(), []frontend.Variable{0, 0, 0, 0}, 4, evals, beta)
	api.AssertIsEqual(out[0].Limb, c.Expected0)
	api.AssertIsEqual(out[1].Limb, c.Expected1)
	return nil
}
func TestInterpolationRecoversKnownPolynomial(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &interpolationPolynomialCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	a := &interpolationPolynomialCircuit{}
	root := gl.PrimitiveRootOfUnity(4)
	for i := 0; i < 16; i++ {
		x := goldilocks.NewElement(0)
		x.Exp(root, big.NewInt(int64(i)))
		xsq := goldilocks.NewElement(0)
		xsq.Square(&x)
		var y goldilocks.Element
		y.SetUint64(3)
		y.Mul(&y, &xsq)
		var twice goldilocks.Element
		twice.SetUint64(2)
		twice.Mul(&twice, &x)
		y.Add(&y, &twice)
		one := goldilocks.NewElement(1)
		y.Add(&y, &one)
		a.Evals[bits.Reverse8(uint8(i))>>4] = y.Uint64()
	}
	for _, tc := range []struct{ b0, b1, e0, e1 int }{{2, 0, 17, 0}, {2, 1, 38, 14}} {
		a.Beta0, a.Beta1, a.Expected0, a.Expected1 = tc.b0, tc.b1, tc.e0, tc.e1
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if e = ccs.IsSolved(w); e != nil {
			t.Fatal(e)
		}
	}
}
