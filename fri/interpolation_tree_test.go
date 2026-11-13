package fri

import (
	"math/big"
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
