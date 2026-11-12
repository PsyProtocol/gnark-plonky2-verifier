package fri

import (
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"math/big"
	"math/rand"
	"testing"
)

type dotCompareCircuit struct {
	Alpha0, Alpha1 frontend.Variable
	Evals          [16]frontend.Variable
	Count          int `gnark:"-"`
}

func (c *dotCompareCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	f := &Chip{api: api, gl: g}
	alpha := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Alpha0), gl.NewVariable(c.Alpha1))
	g.RangeCheckQE(alpha)
	scalars := make([]gl.Variable, c.Count)
	terms := make([]gl.QuadraticExtensionVariable, c.Count)
	for i := range scalars {
		scalars[i] = gl.NewVariable(c.Evals[i])
		terms[i] = scalars[i].ToQuadraticExtension()
	}
	powers := f.precomputeAlphaPowers(alpha, c.Count)
	a := g.ReduceWithPowers(terms, alpha)
	b := f.reduceBaseWithPowers(scalars, powers)
	g.AssertIsEqualExtension(a, b)
	return nil
}
func TestDotMatchesHorner(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for _, n := range []int{0, 1, 2, 8, 16} {
		ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dotCompareCircuit{Count: n})
		if e != nil {
			t.Fatal(e)
		}
		for sample := 0; sample < 12; sample++ {
			var a dotCompareCircuit
			for i := range a.Evals {
				a.Evals[i] = 0
			}
			a.Alpha0 = 0
			a.Alpha1 = 0
			if sample == 1 {
				a.Alpha0 = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
				a.Alpha1 = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
			} else if sample > 1 {
				a.Alpha0 = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
				a.Alpha1 = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
			}
			for i := 0; i < n; i++ {
				if sample == 1 {
					a.Evals[i] = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
				} else {
					a.Evals[i] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
				}
			}
			w, e := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if e != nil {
				t.Fatal(e)
			}
			if e = ccs.IsSolved(w); e != nil {
				t.Fatalf("n=%d case=%d: %v", n, sample, e)
			}
		}
	}
}

type dotBlockCircuit struct {
	X, Expected frontend.Variable
	Count       int `gnark:"-"`
}

func (c *dotBlockCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	f := &Chip{api: api, gl: g}
	v := make([]gl.Variable, c.Count)
	p := make([]gl.QuadraticExtensionVariable, c.Count)
	for i := range v {
		v[i] = gl.NewVariable(c.X)
		p[i] = gl.NewQuadraticExtensionVariable(gl.One(), gl.One())
	}
	r := f.reduceBaseWithPowers(v, p)
	api.AssertIsEqual(r[0].Limb, c.Expected)
	api.AssertIsEqual(r[1].Limb, c.Expected)
	return nil
}
func TestDotBlockBoundary(t *testing.T) {
	for _, n := range []int{8192, 8193} {
		ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dotBlockCircuit{Count: n})
		if e != nil {
			t.Fatal(e)
		}
		x := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
		expected := new(big.Int).Sub(gl.MODULUS, big.NewInt(int64(n)))
		w, e := frontend.NewWitness(&dotBlockCircuit{X: x, Expected: expected}, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if e = ccs.IsSolved(w); e != nil {
			t.Fatalf("n=%d: %v", n, e)
		}
		bad, e := frontend.NewWitness(&dotBlockCircuit{X: gl.MODULUS, Expected: 0}, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if ccs.IsSolved(bad) == nil {
			t.Fatalf("n=%d accepted noncanonical input", n)
		}
	}
}

type dotExpectedCircuit struct {
	Alpha0, Alpha1, Expected0, Expected1 frontend.Variable
	Evals                                [3]frontend.Variable
}

func (c *dotExpectedCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	f := &Chip{api: api, gl: g}
	alpha := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Alpha0), gl.NewVariable(c.Alpha1))
	g.RangeCheckQE(alpha)
	v := make([]gl.Variable, len(c.Evals))
	for i := range v {
		v[i] = gl.NewVariable(c.Evals[i])
	}
	out := f.reduceBaseWithPowers(v, f.precomputeAlphaPowers(alpha, len(v)))
	api.AssertIsEqual(out[0].Limb, c.Expected0)
	api.AssertIsEqual(out[1].Limb, c.Expected1)
	return nil
}
func TestDotKnownExtensionPolynomial(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dotExpectedCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	a := dotExpectedCircuit{Alpha0: 2, Alpha1: 3, Evals: [3]frontend.Variable{5, 7, 11}, Expected0: 756, Expected1: 153}
	w, e := frontend.NewWitness(&a, ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	if e = ccs.IsSolved(w); e != nil {
		t.Fatal(e)
	}
	a.Expected0 = 757
	w, e = frontend.NewWitness(&a, ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	if ccs.IsSolved(w) == nil {
		t.Fatal("accepted incorrect polynomial value")
	}
}

type dotAlphaBoundCircuit struct{ Alpha frontend.Variable }

func (c *dotAlphaBoundCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	f := &Chip{api: api, gl: g}
	p := f.precomputeAlphaPowers(gl.NewVariable(c.Alpha).ToQuadraticExtension(), 2)
	api.AssertIsEqual(p[0][0].Limb, 1)
	return nil
}
func TestDotRejectsNoncanonicalAlpha(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dotAlphaBoundCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		v     frontend.Variable
		valid bool
	}{{0, true}, {1, true}, {new(big.Int).Sub(gl.MODULUS, big.NewInt(1)), true}, {gl.MODULUS, false}, {new(big.Int).Add(gl.MODULUS, big.NewInt(1)), false}} {
		w, e := frontend.NewWitness(&dotAlphaBoundCircuit{Alpha: tc.v}, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		e = ccs.IsSolved(w)
		if (e == nil) != tc.valid {
			t.Errorf("alpha=%v valid=%v error=%v", tc.v, tc.valid, e)
		}
	}
}
