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

// friCombineInitialLegacy preserves the per-query exponentiation for comparison.
func (f *Chip) friCombineInitialLegacy(instance InstanceInfo, proof variables.FriInitialTreeProof, alpha, subgroup gl.QuadraticExtensionVariable, openings []gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	sum := gl.ZeroExtension()
	for i, batch := range instance.Batches {
		evals := make([]gl.QuadraticExtensionVariable, 0, len(batch.Polynomials))
		for _, polynomial := range batch.Polynomials {
			evals = append(evals, proof.EvalsProofs[polynomial.OracleIndex].Elements[polynomial.PolynomialInfo].ToQuadraticExtension())
		}
		reduced := f.gl.ReduceWithPowers(evals, alpha)
		numerator := f.gl.SubExtensionNoReduce(reduced, openings[i])
		denominator := f.gl.SubExtension(subgroup, batch.Point)
		sum = f.gl.MulExtension(f.gl.ExpExtension(alpha, uint64(len(evals))), sum)
		inverse, hasInverse := f.gl.InverseExtension(denominator)
		f.api.AssertIsEqual(hasInverse, 1)
		sum = f.gl.MulAddExtension(numerator, inverse, sum)
	}
	return sum
}

type alphaPowersCircuit struct {
	Alpha0, Alpha1 frontend.Variable
}

func (c *alphaPowersCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	alpha := gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Alpha0), gl.NewVariable(c.Alpha1))
	g.RangeCheckQE(alpha)
	f := &Chip{api: api, gl: g}
	instance := InstanceInfo{Batches: []BatchInfo{
		{Point: gl.NewVariable(3).ToQuadraticExtension()},
		{Point: gl.NewVariable(5).ToQuadraticExtension(), Polynomials: []PolynomialInfo{{0, 0}, {0, 1}}},
		{Point: gl.NewVariable(6).ToQuadraticExtension(), Polynomials: []PolynomialInfo{{0, 0}, {0, 1}, {0, 2}, {0, 3}}},
	}}
	openings := []gl.QuadraticExtensionVariable{gl.ZeroExtension(), gl.NewVariable(11).ToQuadraticExtension(), gl.NewVariable(13).ToQuadraticExtension()}
	powers := f.precomputeAlphaPowers(alpha, 4)
	for _, values := range [][]uint64{{1, 2, 3, 4}, {5, 6, 7, 8}} {
		proof := variables.FriInitialTreeProof{EvalsProofs: []variables.FriEvalProof{{Elements: gl.Uint64ArrayToVariableArray(values)}}}
		subgroup := gl.NewVariable(7 + values[0]).ToQuadraticExtension()
		old := f.friCombineInitialLegacy(instance, proof, alpha, subgroup, openings)
		optimized := f.friCombineInitial(instance, proof, subgroup, openings, powers)
		g.AssertIsEqualExtension(old, optimized)
	}
	return nil
}

func TestAlphaPowersSharedAcrossQueries(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &alphaPowersCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	for _, assignment := range []*alphaPowersCircuit{{0, 0}, {1, 0}, {max, max}, {42, 23}} {
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(witness); err != nil {
			t.Errorf("alpha=(%v,%v): %v", assignment.Alpha0, assignment.Alpha1, err)
		}
	}
}

func TestAlphaPowersSharedGroth16(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &alphaPowersCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&alphaPowersCircuit{Alpha0: 42, Alpha1: 23}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
	if len(ccs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
}
