package fri

import (
	"math/big"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type interpolationTreeCircuit struct {
	Y        [5]frontend.Variable
	Expected frontend.Variable
	Count    int `gnark:"-"`
}

type extensionTreeComparison struct {
	Y, Weight [5][2]frontend.Variable
	Count     int `gnark:"-"`
}

func (c *extensionTreeComparison) Define(api frontend.API) error {
	g := gl.New(api)
	chip := &Chip{api: api, gl: g}
	x := gl.NewQuadraticExtensionVariable(gl.NewVariable(19), gl.NewVariable(3))
	points := make([]gl.QuadraticExtensionVariable, c.Count)
	values := make([]gl.QuadraticExtensionVariable, c.Count)
	weights := make([]gl.QuadraticExtensionVariable, c.Count)
	for i := range points {
		points[i] = gl.NewVariable(i + 2).ToQuadraticExtension()
		values[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Y[i][0]), gl.NewVariable(c.Y[i][1]))
		weights[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Weight[i][0]), gl.NewVariable(c.Weight[i][1]))
		g.RangeCheckQE(weights[i])
	}
	current := chip.interpolateChecked(x, points, values, weights, false)
	prefix := make([]gl.QuadraticExtensionVariable, c.Count+1)
	differences := make([]gl.QuadraticExtensionVariable, c.Count)
	prefix[0] = gl.OneExtension()
	for i := range points {
		differences[i] = g.SubExtension(x, points[i])
		prefix[i+1] = g.MulExtension(prefix[i], differences[i])
	}
	api.AssertIsEqual(g.IsZero(prefix[c.Count]), 0)
	suffix, old := gl.OneExtension(), gl.ZeroExtension()
	for i := c.Count - 1; i >= 0; i-- {
		others := g.MulExtension(prefix[i], suffix)
		weighted := g.MulExtension(values[i], weights[i])
		old = g.MulAddExtensionCanonical(weighted, others, old)
		if i != 0 {
			suffix = g.MulExtension(suffix, differences[i])
		}
	}
	g.AssertIsEqualExtension(current, old)
	return nil
}

func TestInterpolationTreeExtensionLeaves(t *testing.T) {
	rng := rand.New(rand.NewSource(239))
	for _, n := range []int{1, 3, 5} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &extensionTreeComparison{Count: n})
		if err != nil {
			t.Fatal(err)
		}
		for sample := 0; sample < 8; sample++ {
			a := extensionTreeComparison{Count: n}
			for i := range a.Y {
				for j := range a.Y[i] {
					if sample == 0 {
						a.Y[i][j] = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
						a.Weight[i][j] = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
					} else {
						a.Y[i][j] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
						a.Weight[i][j] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
					}
				}
			}
			w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(w); err != nil {
				t.Fatalf("size %d sample %d: %v", n, sample, err)
			}
		}
	}
}

func TestInterpolationTreeSumBounds(t *testing.T) {
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	// Two extension products contribute at most 2*(1+W)*(p-1)^2
	// to the first coefficient; the second is bounded by 4*(p-1)^2.
	square := new(big.Int).Mul(max, max)
	first := new(big.Int).Mul(new(big.Int).Set(square), big.NewInt(int64(2*(1+gl.W))))
	second := new(big.Int).Mul(new(big.Int).Set(square), big.NewInt(4))
	host := ecc.BN254.ScalarField()
	for _, value := range []*big.Int{first, second} {
		if new(big.Int).Div(new(big.Int).Set(value), gl.MODULUS).BitLen() > 80 || value.Cmp(host) >= 0 {
			t.Fatal("interpolation sum exceeds quotient or host-field bound")
		}
	}
	if new(big.Int).Lsh(new(big.Int).Set(gl.MODULUS), 80).Cmp(host) >= 0 {
		t.Fatal("an 80-bit quotient could wrap the host field")
	}
	// Two unreduced extension-product leaves, each multiplied by a
	// canonical extension value, contribute less than 44p³ to c0.
	cube := new(big.Int).Mul(new(big.Int).Set(square), max)
	lazy := new(big.Int).Mul(cube, big.NewInt(44))
	if new(big.Int).Div(new(big.Int).Set(lazy), gl.MODULUS).BitLen() > 144 || lazy.Cmp(host) >= 0 {
		t.Fatal("lazy leaf sum exceeds quotient or host-field bound")
	}
	if new(big.Int).Lsh(new(big.Int).Set(gl.MODULUS), 144).Cmp(host) >= 0 {
		t.Fatal("a 144-bit quotient could wrap the host field")
	}
}

func (c *interpolationTreeCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	chip := &Chip{api: api, gl: g}
	x := gl.NewVariable(19).ToQuadraticExtension()
	points := make([]gl.QuadraticExtensionVariable, c.Count)
	values := make([]gl.QuadraticExtensionVariable, c.Count)
	weights := make([]gl.QuadraticExtensionVariable, c.Count)
	for i := range points {
		points[i] = gl.NewVariable(i + 2).ToQuadraticExtension()
		values[i] = gl.NewVariable(c.Y[i]).ToQuadraticExtension()
		weights[i] = gl.NewVariable(i + 1).ToQuadraticExtension()
	}
	result := chip.interpolateChecked(x, points, values, weights, false)
	api.AssertIsEqual(result[0].Limb, c.Expected)
	api.AssertIsEqual(result[1].Limb, 0)
	return nil
}

func TestInterpolationTreeUnevenSizes(t *testing.T) {
	for _, n := range []int{0, 1, 3, 5} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &interpolationTreeCircuit{Count: n})
		if err != nil {
			t.Fatal(err)
		}
		if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
			t.Fatal("unexpected commitment")
		}
		expected := new(big.Int)
		assignment := interpolationTreeCircuit{Count: n}
		for i := range assignment.Y {
			assignment.Y[i] = i + 3
		}
		for i := 0; i < n; i++ {
			term := big.NewInt(int64((i + 3) * (i + 1)))
			for j := 0; j < n; j++ {
				if i != j {
					term.Mul(term, big.NewInt(int64(19-(j+2))))
				}
			}
			expected.Add(expected, term)
		}
		assignment.Expected = expected.Mod(expected, gl.MODULUS)
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		assignment.Expected = new(big.Int).Add(expected, big.NewInt(1))
		w, err = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err == nil {
			t.Fatalf("size %d: accepted incorrect result", n)
		}
	}
}
