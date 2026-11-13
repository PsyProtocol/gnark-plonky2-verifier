package plonk

import (
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/plonk/gates"
	"github.com/cf/gnark-plonky2-verifier/variables"
)

func (p *PlonkChip) legacyEvalVanishingPoly(
	vars gates.EvaluationVars,
	proofChallenges variables.ProofChallenges,
	openings variables.OpeningSet,
	zetaPowN gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	glApi := gl.New(p.api)
	constraintTerms := p.evaluateGatesChip.EvaluateGateConstraints(vars)

	// Calculate the k[i] * x
	sIDs := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		sIDs[i] = glApi.ScalarMulExtension(proofChallenges.PlonkZeta, p.commonDataKIs[i])
	}

	// Calculate L_0(zeta)
	l0Zeta := p.evalL0(proofChallenges.PlonkZeta, zetaPowN)

	vanishingZ1Terms := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumChallenges)
	vanishingPartialProductsTerms := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := glApi.MulExtension(
			l0Zeta,
			glApi.SubExtension(openings.PlonkZs[i], gl.OneExtension()))
		vanishingZ1Terms = append(vanishingZ1Terms, z1_term)

		numeratorValues := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumRoutedWires)
		denominatorValues := make([]gl.QuadraticExtensionVariable, 0, p.commonData.Config.NumRoutedWires)
		for j := uint64(0); j < p.commonData.Config.NumRoutedWires; j++ {
			// The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
			// `beta * s_sigma + wire_value + gamma`.
			wireValuePlusGamma := glApi.AddExtension(
				openings.Wires[j],
				gl.NewQuadraticExtensionVariable(proofChallenges.PlonkGammas[i], gl.Zero()),
			)

			numerator := glApi.AddExtension(
				glApi.MulExtension(
					gl.NewQuadraticExtensionVariable(proofChallenges.PlonkBetas[i], gl.Zero()),
					sIDs[j],
				),
				wireValuePlusGamma,
			)

			denominator := glApi.AddExtension(
				glApi.MulExtension(
					gl.NewQuadraticExtensionVariable(proofChallenges.PlonkBetas[i], gl.Zero()),
					openings.PlonkSigmas[j],
				),
				wireValuePlusGamma,
			)

			numeratorValues = append(numeratorValues, numerator)
			denominatorValues = append(denominatorValues, denominator)
		}

		vanishingPartialProductsTerms = append(
			vanishingPartialProductsTerms,
			p.checkPartialProducts(numeratorValues, denominatorValues, i, openings)...,
		)
	}

	vanishingTerms := append(vanishingZ1Terms, vanishingPartialProductsTerms...)
	vanishingTerms = append(vanishingTerms, constraintTerms...)

	reducedValues := make([]gl.QuadraticExtensionVariable, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		reducedValues[i] = gl.ZeroExtension()
	}

	// reverse iterate the vanishingPartialProductsTerms array
	for i := len(vanishingTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			reducedValues[j] = glApi.AddExtension(
				vanishingTerms[i],
				glApi.ScalarMulExtension(
					reducedValues[j],
					proofChallenges.PlonkAlphas[j],
				),
			)
		}
	}

	return reducedValues
}
