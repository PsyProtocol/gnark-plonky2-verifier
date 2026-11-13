package fri

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type subgroupExponentCircuit struct {
	Bits     [8]frontend.Variable
	Expected frontend.Variable
}

func (c *subgroupExponentCircuit) Define(api frontend.API) error {
	f := &Chip{api: api, gl: gl.New(api)}
	result := f.expFromBitsConstBase(gl.PrimitiveRootOfUnity(16), c.Bits[:])
	api.AssertIsEqual(result.Limb, c.Expected)
	return nil
}

func TestSubgroupExponent(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &subgroupExponentCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	base := gl.PrimitiveRootOfUnity(16)
	var baseInt big.Int
	base.BigInt(&baseInt)
	var assignment subgroupExponentCircuit
	for _, exponent := range []int{0, 1, 2, 17, 85, 127, 128, 255} {
		for i := range assignment.Bits {
			assignment.Bits[i] = (exponent >> i) & 1
		}
		assignment.Expected = new(big.Int).Exp(&baseInt, big.NewInt(int64(exponent)), gl.MODULUS)
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("exponent %d: %v", exponent, err)
		}
	}
	assignment.Bits[0] = 2
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(w); err == nil {
		t.Fatal("accepted a non-boolean exponent bit")
	}
	assignment.Bits[0] = 1
	w, err = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
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
