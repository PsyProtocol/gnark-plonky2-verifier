package fri

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type groupedHornerCircuit struct {
	Point  gl.Variable
	Coeffs []gl.QuadraticExtensionVariable
}

func (c *groupedHornerCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	g.RangeCheck(c.Point)
	for _, coefficient := range c.Coeffs {
		g.RangeCheckQE(coefficient)
	}
	f := &Chip{api: api, gl: g}
	polynomial := variables.PolynomialCoeffs{Coeffs: c.Coeffs}
	g.AssertIsEqualExtension(f.finalPolyEvalGrouped(polynomial, c.Point), f.finalPolyEval(polynomial, c.Point.ToQuadraticExtension()))
	return nil
}

func TestGroupedHornerMatchesLegacy(t *testing.T) {
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	for _, length := range []int{0, 1, 2, 3, 7, 16} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &groupedHornerCircuit{Coeffs: make([]gl.QuadraticExtensionVariable, length)})
		if err != nil {
			t.Fatal(err)
		}
		for _, point := range []frontend.Variable{0, 1, max, 17} {
			a := &groupedHornerCircuit{Point: gl.NewVariable(point), Coeffs: make([]gl.QuadraticExtensionVariable, length)}
			for i := range a.Coeffs {
				a.Coeffs[i] = gl.NewQuadraticExtensionVariable(gl.NewVariable(max), gl.NewVariable(i))
			}
			w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(w); err != nil {
				t.Fatalf("length=%d point=%v: %v", length, point, err)
			}
			if length == 16 && point == 17 {
				pk, vk, err := groth16.Setup(cs)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := groth16.Prove(cs, pk, w)
				if err != nil {
					t.Fatal(err)
				}
				public, err := w.Public()
				if err != nil {
					t.Fatal(err)
				}
				if err := groth16.Verify(proof, vk, public); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
			t.Fatal("unexpected commitment")
		}
	}
}
