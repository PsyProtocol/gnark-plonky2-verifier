package fri

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type queryRangeCircuit struct {
	Oracle0, Oracle1, Step0, Step1 frontend.Variable
}

func (c *queryRangeCircuit) Define(api frontend.API) error {
	proof := variables.FriProof{QueryRoundProofs: []variables.FriQueryRound{{
		InitialTreesProof: variables.FriInitialTreeProof{EvalsProofs: []variables.FriEvalProof{
			{Elements: []gl.Variable{gl.NewVariable(c.Oracle0), gl.NewVariable(c.Oracle1)}},
		}},
		Steps: []variables.FriQueryStep{{Evals: []gl.QuadraticExtensionVariable{
			gl.NewQuadraticExtensionVariable(gl.NewVariable(c.Step0), gl.NewVariable(c.Step1)),
		}}},
	}}}
	(&Chip{api: api, gl: gl.New(api)}).rangeCheckQueryEvaluations(&proof)
	return nil
}

func TestQueryRangeRejectsNoncanonicalInputs(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &queryRangeCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	for i := -1; i < 4; i++ {
		values := [4]frontend.Variable{max, max, max, max}
		if i >= 0 {
			values[i] = gl.MODULUS
		}
		a := queryRangeCircuit{values[0], values[1], values[2], values[3]}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w)
		if (err == nil) != (i == -1) {
			t.Fatalf("field %d: solve error %v", i, err)
		}
	}
}
