package challenger

import (
	"fmt"

	"github.com/cf/gnark-plonky2-verifier/fri"
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark/frontend"
)

type absorptionMode uint8

const (
	reduceInput absorptionMode = iota
	checkCanonicalInput
	canonicalByConstruction
)

type bufferedInput struct {
	value gl.Variable
	mode  absorptionMode
}

type Chip struct {
	api               frontend.API `gnark:"-"`
	poseidonChip      *poseidon.GoldilocksChip
	poseidonBN254Chip *poseidon.BN254Chip
	spongeState       poseidon.GoldilocksState
	inputBuffer       []bufferedInput
	outputBuffer      []gl.Variable
}

func NewChip(api frontend.API) *Chip {
	var spongeState poseidon.GoldilocksState
	var inputBuffer []bufferedInput
	var outputBuffer []gl.Variable
	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		spongeState[i] = gl.Zero()
	}
	poseidonChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &Chip{
		api:               api,
		poseidonChip:      poseidonChip,
		poseidonBN254Chip: poseidonBN254Chip,
		spongeState:       spongeState,
		inputBuffer:       inputBuffer,
		outputBuffer:      outputBuffer,
	}
}

func (c *Chip) ObserveElement(element gl.Variable) {
	c.observeElement(element, reduceInput)
}

func (c *Chip) observeElement(element gl.Variable, mode absorptionMode) {
	// Clear the output buffer
	c.outputBuffer = make([]gl.Variable, 0)
	c.inputBuffer = append(c.inputBuffer, bufferedInput{value: element, mode: mode})
	if len(c.inputBuffer) == poseidon.SPONGE_RATE {
		c.duplexing()
	}
}

func (c *Chip) ObserveElements(elements []gl.Variable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *Chip) ObserveHash(hash poseidon.GoldilocksHashOut) {
	elements := c.poseidonChip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *Chip) ObserveBN254Hash(hash poseidon.BN254HashOut) {
	elements := c.poseidonBN254Chip.ToVec(hash)
	// ToVec constrains each chunk to at most 56 bits, strictly below p.
	for _, element := range elements {
		c.observeElement(element, canonicalByConstruction)
	}
}

func (c *Chip) ObserveCap(cap []poseidon.BN254HashOut) {
	for i := 0; i < len(cap); i++ {
		c.ObserveBN254Hash(cap[i])
	}
}

func (c *Chip) ObserveExtensionElement(element gl.QuadraticExtensionVariable) {
	c.ObserveElements(element[:])
}

func (c *Chip) ObserveExtensionElements(elements []gl.QuadraticExtensionVariable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveExtensionElement(elements[i])
	}
}

func (c *Chip) ObserveOpenings(openings fri.Openings) {
	for i := 0; i < len(openings.Batches); i++ {
		c.ObserveExtensionElements(openings.Batches[i].Values)
	}
}

// ObserveCheckedOpenings range-checks each component when it is absorbed.
// Checking at absorption also covers expressions changed while buffered.
func (c *Chip) ObserveCheckedOpenings(openings fri.Openings) {
	for _, batch := range openings.Batches {
		for _, element := range batch.Values {
			c.observeElement(element[0], checkCanonicalInput)
			c.observeElement(element[1], checkCanonicalInput)
		}
	}
}

func (c *Chip) GetChallenge() gl.Variable {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *Chip) GetNChallenges(n uint64) []gl.Variable {
	challenges := make([]gl.Variable, n)
	for i := uint64(0); i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func (c *Chip) GetExtensionChallenge() gl.QuadraticExtensionVariable {
	values := c.GetNChallenges(2)
	return gl.QuadraticExtensionVariable{values[0], values[1]}
}

func (c *Chip) GetHash() poseidon.GoldilocksHashOut {
	return [poseidon.POSEIDON_GL_HASH_SIZE]gl.Variable{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *Chip) GetFriChallenges(
	commitPhaseMerkleCaps []variables.FriMerkleCap,
	finalPoly variables.PolynomialCoeffs,
	powWitness gl.Variable,
	degreeBits uint64,
	config types.FriConfig,
) variables.FriChallenges {
	return c.getFriChallenges(commitPhaseMerkleCaps, finalPoly, powWitness, degreeBits, config, false)
}

// GetFriChallengesChecked constrains final polynomial coefficients and the
// proof-of-work witness before they are absorbed into the transcript.
func (c *Chip) GetFriChallengesChecked(
	commitPhaseMerkleCaps []variables.FriMerkleCap,
	finalPoly variables.PolynomialCoeffs,
	powWitness gl.Variable,
	degreeBits uint64,
	config types.FriConfig,
) variables.FriChallenges {
	return c.getFriChallenges(commitPhaseMerkleCaps, finalPoly, powWitness, degreeBits, config, true)
}

func (c *Chip) getFriChallenges(
	commitPhaseMerkleCaps []variables.FriMerkleCap,
	finalPoly variables.PolynomialCoeffs,
	powWitness gl.Variable,
	degreeBits uint64,
	config types.FriConfig,
	checked bool,
) variables.FriChallenges {
	numFriQueries := config.NumQueryRounds
	friAlpha := c.GetExtensionChallenge()

	var friBetas []gl.QuadraticExtensionVariable
	for i := 0; i < len(commitPhaseMerkleCaps); i++ {
		c.ObserveCap(commitPhaseMerkleCaps[i])
		friBetas = append(friBetas, c.GetExtensionChallenge())
	}

	if checked {
		for _, element := range finalPoly.Coeffs {
			c.observeElement(element[0], checkCanonicalInput)
			c.observeElement(element[1], checkCanonicalInput)
		}
		c.observeElement(powWitness, checkCanonicalInput)
	} else {
		c.ObserveExtensionElements(finalPoly.Coeffs)
		c.ObserveElement(powWitness)
	}

	friPowResponse := c.GetChallenge()
	friQueryIndices := c.GetNChallenges(numFriQueries)

	return variables.FriChallenges{
		FriAlpha:        friAlpha,
		FriBetas:        friBetas,
		FriPowResponse:  friPowResponse,
		FriQueryIndices: friQueryIndices,
	}
}

func (c *Chip) duplexing() {
	if len(c.inputBuffer) > poseidon.SPONGE_RATE {
		fmt.Println(len(c.inputBuffer))
		panic("something went wrong")
	}

	glApi := gl.New(c.api)

	for i := 0; i < len(c.inputBuffer); i++ {
		input := c.inputBuffer[i]
		switch input.mode {
		case reduceInput:
			c.spongeState[i] = glApi.Reduce(input.value)
		case checkCanonicalInput:
			glApi.RangeCheck(input.value)
			c.spongeState[i] = input.value
		case canonicalByConstruction:
			c.spongeState[i] = input.value
		default:
			panic("invalid transcript absorption mode")
		}
	}
	// Clear the input buffer
	c.inputBuffer = make([]bufferedInput, 0)
	c.spongeState = c.poseidonChip.Poseidon(c.spongeState)

	// Clear the output buffer
	c.outputBuffer = make([]gl.Variable, 0)
	for i := 0; i < poseidon.SPONGE_RATE; i++ {
		c.outputBuffer = append(c.outputBuffer, c.spongeState[i])
	}
}
