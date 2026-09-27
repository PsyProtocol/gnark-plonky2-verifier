package verifier

import (
	"github.com/cf/gnark-plonky2-verifier/challenger"
	"github.com/cf/gnark-plonky2-verifier/fri"
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/plonk"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark/frontend"
)

type VerifierChip struct {
	api               frontend.API             `gnark:"-"`
	glChip            *gl.Chip                 `gnark:"-"`
	poseidonGlChip    *poseidon.GoldilocksChip `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip      `gnark:"-"`
	plonkChip         *plonk.PlonkChip         `gnark:"-"`
	friChip           *fri.Chip                `gnark:"-"`
	commonData        types.CommonCircuitData  `gnark:"-"`
}

func NewVerifierChip(api frontend.API, commonCircuitData types.CommonCircuitData) *VerifierChip {
	glChip := gl.New(api)
	friChip := fri.NewChip(api, &commonCircuitData, &commonCircuitData.FriParams)
	plonkChip := plonk.NewPlonkChip(api, commonCircuitData)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &VerifierChip{
		api:               api,
		glChip:            glChip,
		poseidonGlChip:    poseidonGlChip,
		poseidonBN254Chip: poseidonBN254Chip,
		plonkChip:         plonkChip,
		friChip:           friChip,
		commonData:        commonCircuitData,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []gl.Variable) poseidon.GoldilocksHashOut {
	return c.poseidonGlChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(
	proof variables.Proof,
	publicInputsHash poseidon.GoldilocksHashOut,
	verifierData variables.VerifierOnlyCircuitData,
) variables.ProofChallenges {
	friConfig := c.commonData.FriParams.Config
	numChallenges := c.commonData.Config.NumChallenges
	challenger := challenger.NewChip(c.api)

	// Challenge order matching plonky2-hwa prover (see plonky2/src/plonk/get_challenges.rs)
	// Observes fri_params (FriParams::observe), which includes FriConfig then extra FriParams fields.
	// 1a. Observe FRI config (rate_bits, cap_height, proof_of_work_bits, reduction_strategy.serialize(), num_query_rounds)
	challenger.ObserveElement(gl.NewVariable(friConfig.RateBits))
	challenger.ObserveElement(gl.NewVariable(friConfig.CapHeight))
	challenger.ObserveElement(gl.NewVariable(friConfig.ProofOfWorkBits))
	// Observe reduction strategy (variant indicator + params based on strategy type)
	challenger.ObserveElement(gl.NewVariable(friConfig.ReductionStrategy.Variant))
	if friConfig.ReductionStrategy.Variant == 0 {
		// Fixed strategy: observe all arity bits
		for _, arityBit := range friConfig.ReductionStrategy.FixedArityBits {
			challenger.ObserveElement(gl.NewVariable(arityBit))
		}
	} else if friConfig.ReductionStrategy.Variant == 1 {
		// ConstantArityBits strategy: observe arity_bits and final_poly_bits
		challenger.ObserveElement(gl.NewVariable(friConfig.ReductionStrategy.ArityBits))
		challenger.ObserveElement(gl.NewVariable(friConfig.ReductionStrategy.FinalPolyBits))
	} else {
		// MinSize strategy: observe max_arity_bits (0 if None)
		challenger.ObserveElement(gl.NewVariable(friConfig.ReductionStrategy.MaxArityBits))
	}
	challenger.ObserveElement(gl.NewVariable(friConfig.NumQueryRounds))
	// 1b. Observe extra FriParams fields (hiding, degree_bits, reduction_arity_bits)
	// These are observed by FriParams::observe in plonky2-hwa but were missing here.
	hidingVal := uint64(0)
	if c.commonData.FriParams.Hiding {
		hidingVal = 1
	}
	challenger.ObserveElement(gl.NewVariable(hidingVal))
	challenger.ObserveElement(gl.NewVariable(c.commonData.FriParams.DegreeBits))
	for _, arityBit := range c.commonData.FriParams.ReductionArityBits {
		challenger.ObserveElement(gl.NewVariable(arityBit))
	}
	// 2. Observe circuit digest and public inputs hash
	challenger.ObserveBN254Hash(verifierData.CircuitDigest)
	challenger.ObserveHash(publicInputsHash)
	// 3. Observe caps and get challenges
	challenger.ObserveCap(proof.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)
	challenger.ObserveCap(proof.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)
	challenger.ObserveCap(proof.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()
	challenger.ObserveOpenings(c.friChip.ToOpenings(proof.Openings))

	friChallenges := challenger.GetFriChallenges(
		proof.OpeningProof.CommitPhaseMerkleCaps,
		proof.OpeningProof.FinalPoly,
		proof.OpeningProof.PowWitness,
		uint64(c.commonData.FriParams.DegreeBits),
		friConfig,
	)

	return variables.ProofChallenges{
		PlonkBetas:    plonkBetas,
		PlonkGammas:   plonkGammas,
		PlonkAlphas:   plonkAlphas,
		PlonkZeta:     plonkZeta,
		FriChallenges: friChallenges,
	}
}

func (c *VerifierChip) rangeCheckProof(proof variables.Proof) {
	// Need to verify the plonky2 proof's openings, openings proof (other than the sibling elements), fri's final poly, pow witness.

	// Note that this is NOT range checking the public inputs (first 32 elements should be no more than 8 bits and the last 4 elements should be no more than 64 bits).  Since this is currently being inputted via the smart contract,
	// we will assume that caller is doing that check.

	// Range check the proof's openings.
	for _, constant := range proof.Openings.Constants {
		c.glChip.RangeCheckQE(constant)
	}

	for _, plonkSigma := range proof.Openings.PlonkSigmas {
		c.glChip.RangeCheckQE(plonkSigma)
	}

	for _, wire := range proof.Openings.Wires {
		c.glChip.RangeCheckQE(wire)
	}

	for _, plonkZ := range proof.Openings.PlonkZs {
		c.glChip.RangeCheckQE(plonkZ)
	}

	for _, plonkZNext := range proof.Openings.PlonkZsNext {
		c.glChip.RangeCheckQE(plonkZNext)
	}

	for _, partialProduct := range proof.Openings.PartialProducts {
		c.glChip.RangeCheckQE(partialProduct)
	}

	for _, quotientPoly := range proof.Openings.QuotientPolys {
		c.glChip.RangeCheckQE(quotientPoly)
	}

	// Range check the openings proof.
	for _, queryRound := range proof.OpeningProof.QueryRoundProofs {
		for _, evalsProof := range queryRound.InitialTreesProof.EvalsProofs {
			for _, evalsProofElement := range evalsProof.Elements {
				c.glChip.RangeCheck(evalsProofElement)
			}
		}

		for _, queryStep := range queryRound.Steps {
			for _, eval := range queryStep.Evals {
				c.glChip.RangeCheckQE(eval)
			}
		}
	}

	// Range check the fri's final poly.
	for _, coeff := range proof.OpeningProof.FinalPoly.Coeffs {
		c.glChip.RangeCheckQE(coeff)
	}

	// Range check the pow witness.
	c.glChip.RangeCheck(proof.OpeningProof.PowWitness)
}

func (c *VerifierChip) Verify(
	proof variables.Proof,
	publicInputs []gl.Variable,
	verifierData variables.VerifierOnlyCircuitData,
) {
	c.rangeCheckProof(proof)

	// Generate the parts of the witness that is for the plonky2 proof input
	publicInputsHash := c.GetPublicInputsHash(publicInputs)
	proofChallenges := c.GetChallenges(proof, publicInputsHash, verifierData)

	c.plonkChip.Verify(proofChallenges, proof.Openings, publicInputsHash)

	initialMerkleCaps := []variables.FriMerkleCap{
		verifierData.ConstantSigmasCap,
		proof.WiresCap,
		proof.PlonkZsPartialProductsCap,
		proof.QuotientPolysCap,
	}

	c.friChip.VerifyFriProof(
		c.friChip.GetInstance(proofChallenges.PlonkZeta),
		c.friChip.ToOpenings(proof.Openings),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proof.OpeningProof,
	)
}
