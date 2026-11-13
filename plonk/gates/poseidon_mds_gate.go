package gates

import (
	"regexp"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/zilong-dai/gnark/frontend"
)

var poseidonMdsGateRegex = regexp.MustCompile("PoseidonMdsGate.*")

func deserializePoseidonMdsGate(parameters map[string]string) Gate {
	// Has the format "PoseidonMdsGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>"
	return NewPoseidonMdsGate()
}

type PoseidonMdsGate struct {
}

func NewPoseidonMdsGate() *PoseidonMdsGate {
	return &PoseidonMdsGate{}
}

func (g *PoseidonMdsGate) Id() string {
	return "PoseidonMdsGate"
}

func (g *PoseidonMdsGate) WireInput(i uint64) Range {
	if i >= poseidon.SPONGE_WIDTH {
		panic("Input less than sponge width")
	}
	return Range{i * gl.D, (i + 1) * gl.D}
}

func (g *PoseidonMdsGate) WireOutput(i uint64) Range {
	if i >= poseidon.SPONGE_WIDTH {
		panic("Input less than sponge width")
	}
	return Range{(poseidon.SPONGE_WIDTH + i) * gl.D, (poseidon.SPONGE_WIDTH + i + 1) * gl.D}
}

func (g *PoseidonMdsGate) mdsLayerAlgebra(
	state [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable,
	api frontend.API,
) [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable {
	// The matrix coefficients are base-field scalars, so each algebra
	// coordinate is an independent extension-field MDS layer.
	chip := poseidon.NewGoldilocksChip(api)
	var result [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable
	for coordinate := 0; coordinate < int(gl.D); coordinate++ {
		var layer poseidon.GoldilocksStateExtension
		for i := range layer {
			layer[i] = state[i][coordinate]
		}
		output := chip.MdsLayerExtension(layer)
		for i := range output {
			result[i][coordinate] = output[i]
		}
	}
	return result
}

func (g *PoseidonMdsGate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	constraints := []gl.QuadraticExtensionVariable{}

	var inputs [poseidon.SPONGE_WIDTH]gl.QuadraticExtensionAlgebraVariable
	for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
		inputs[i] = vars.GetLocalExtAlgebra(g.WireInput(i))
	}

	computed_outputs := g.mdsLayerAlgebra(inputs, api)

	for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
		output := vars.GetLocalExtAlgebra(g.WireOutput(i))
		diff := glApi.SubExtensionAlgebra(output, computed_outputs[i])
		for i := 0; i < gl.D; i++ {
			constraints = append(constraints, diff[i])
		}
	}

	return constraints
}
