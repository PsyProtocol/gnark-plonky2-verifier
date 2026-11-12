package fri

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/zilong-dai/gnark/frontend"
)

type Chip struct {
	api               frontend.API             `gnark:"-"`
	gl                *gl.Chip                 `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip      `gnark:"-"`
	commonData        *types.CommonCircuitData `gnark:"-"`
	friParams         *types.FriParams         `gnark:"-"`
}

func NewChip(
	api frontend.API,
	commonData *types.CommonCircuitData,
	friParams *types.FriParams,
) *Chip {
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &Chip{
		api:               api,
		poseidonBN254Chip: poseidonBN254Chip,
		commonData:        commonData,
		friParams:         friParams,
		gl:                gl.New(api),
	}
}

func (f *Chip) GetInstance(zeta gl.QuadraticExtensionVariable) InstanceInfo {
	zetaBatch := BatchInfo{
		Point:       zeta,
		Polynomials: friAllPolys(f.commonData),
	}

	g := gl.PrimitiveRootOfUnity(f.commonData.DegreeBits)
	zetaNext := f.gl.MulExtension(
		gl.NewVariable(g.Uint64()).ToQuadraticExtension(),
		zeta,
	)

	zetaNextBatch := BatchInfo{
		Point:       zetaNext,
		Polynomials: friZSPolys(f.commonData),
	}

	return InstanceInfo{
		Oracles: friOracles(f.commonData),
		Batches: []BatchInfo{zetaBatch, zetaNextBatch},
	}
}

func (f *Chip) ToOpenings(c variables.OpeningSet) Openings {
	values := c.Constants                         // num_constants + 1
	values = append(values, c.PlonkSigmas...)     // num_routed_wires
	values = append(values, c.Wires...)           // num_wires
	values = append(values, c.PlonkZs...)         // num_challenges
	values = append(values, c.PartialProducts...) // num_challenges * num_partial_products
	values = append(values, c.QuotientPolys...)   // num_challenges * quotient_degree_factor
	zetaBatch := OpeningBatch{Values: values}
	zetaNextBatch := OpeningBatch{Values: c.PlonkZsNext}
	return Openings{Batches: []OpeningBatch{zetaBatch, zetaNextBatch}}
}

func (f *Chip) assertLeadingZeros(powWitness gl.Variable, friConfig types.FriConfig) {
	// Asserts that powWitness'es big-endian bit representation has at least friConfig.ProofOfWorkBits leading zeros.
	// Note that this is assuming that the Goldilocks field is being used.  Specfically that the
	// field is 64 bits long.
	f.gl.RangeCheckWithMaxBits(powWitness, 64-friConfig.ProofOfWorkBits)
}

func (f *Chip) fromOpeningsAndAlpha(
	openings *Openings,
	alpha gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	// One reduced opening for all openings evaluated at point Zeta.
	// Another one for all openings evaluated at point Zeta * Omega (which is only PlonkZsNext polynomial)

	reducedOpenings := make([]gl.QuadraticExtensionVariable, 0, 2)
	for _, batch := range openings.Batches {
		reducedOpenings = append(reducedOpenings, f.gl.ReduceWithPowers(batch.Values, alpha))
	}

	return reducedOpenings
}

func (f *Chip) verifyMerkleProofToCapWithCapIndex(
	leafData []gl.Variable,
	leafIndexBits []frontend.Variable,
	capIndexBits []frontend.Variable,
	merkleCap variables.FriMerkleCap,
	proof *variables.FriMerkleProof,
) {
	currentDigest := f.poseidonBN254Chip.HashOrNoop(leafData)
	for i, sibling := range proof.Siblings {
		bit := leafIndexBits[i]

		var inputs poseidon.BN254State
		inputs[0] = frontend.Variable(0)
		inputs[1] = frontend.Variable(0)
		inputs[2] = f.api.Select(bit, sibling, currentDigest)
		inputs[3] = f.api.Select(bit, currentDigest, sibling)
		state := f.poseidonBN254Chip.Poseidon(inputs)

		currentDigest = state[0]
	}

	// We assume that the cap_height is 4.  Create two levels of the Lookup2 circuit
	if len(capIndexBits) != 4 || len(merkleCap) != 16 {
		errorMsg, _ := fmt.Printf(
			"capIndexBits length should be 4 and the merkleCap length should be 16.  Actual values (capIndexBits: %d, merkleCap: %d)\n",
			len(capIndexBits),
			len(merkleCap),
		)
		panic(errorMsg)
	}

	const NUM_LEAF_LOOKUPS = 4
	// Each lookup gadget will connect to 4 merkleCap entries
	const STRIDE_LENGTH = 4
	var leafLookups [NUM_LEAF_LOOKUPS]poseidon.BN254HashOut
	// First create the "leaf" lookup2 circuits
	// This will use the least significant bits of the capIndexBits array
	for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
		leafLookups[i] = f.api.Lookup2(
			capIndexBits[0], capIndexBits[1],
			merkleCap[i*STRIDE_LENGTH], merkleCap[i*STRIDE_LENGTH+1], merkleCap[i*STRIDE_LENGTH+2], merkleCap[i*STRIDE_LENGTH+3],
		)
	}

	// Use the most 2 significant bits of the capIndexBits array for the "root" lookup
	merkleCapEntry := f.api.Lookup2(capIndexBits[2], capIndexBits[3], leafLookups[0], leafLookups[1], leafLookups[2], leafLookups[3])
	f.api.AssertIsEqual(currentDigest, merkleCapEntry)
}

func (f *Chip) verifyInitialProof(xIndexBits []frontend.Variable, proof *variables.FriInitialTreeProof, initialMerkleCaps []variables.FriMerkleCap, capIndexBits []frontend.Variable) {
	if len(proof.EvalsProofs) != len(initialMerkleCaps) {
		panic("length of eval proofs in fri proof should equal length of initial merkle caps")
	}

	for i := 0; i < len(initialMerkleCaps); i++ {
		evals := proof.EvalsProofs[i].Elements
		merkleProof := proof.EvalsProofs[i].MerkleProof
		cap := initialMerkleCaps[i]
		f.verifyMerkleProofToCapWithCapIndex(evals, xIndexBits, capIndexBits, cap, &merkleProof)
	}
}

func (f *Chip) expFromBitsConstBase(
	base goldilocks.Element,
	exponentBits []frontend.Variable,
) gl.Variable {
	product := gl.One()
	for i, bit := range exponentBits {
		// If the bit is 1, we multiply product by base^pow.
		// We can arithmetize this as:
		//     product *= 1 + bit (base^pow - 1)
		//     product = (base^pow - 1) product bit + product
		pow := int64(1 << i)
		basePow := goldilocks.NewElement(0)
		basePow.Exp(base, big.NewInt(pow))
		basePowVariable := gl.NewVariable(basePow.Uint64() - 1)
		product = f.gl.Add(
			f.gl.Mul(
				f.gl.Mul(
					basePowVariable,
					product,
				),
				gl.NewVariable(bit),
			),
			product,
		)
	}
	return product
}

func (f *Chip) calculateSubgroupX(
	xIndexBits []frontend.Variable,
	nLog uint64,
) gl.Variable {
	// Compute x from its index
	// `subgroup_x` is `subgroup[x_index]`, i.e., the actual field element in the domain.
	// OPTIMIZE - Make these as global values
	g := gl.NewVariable(gl.MULTIPLICATIVE_GROUP_GENERATOR.Uint64())
	base := gl.PrimitiveRootOfUnity(nLog)

	// Create a reverse list of xIndexBits
	xIndexBitsRev := make([]frontend.Variable, 0)
	for i := len(xIndexBits) - 1; i >= 0; i-- {
		xIndexBitsRev = append(xIndexBitsRev, xIndexBits[i])
	}

	product := f.expFromBitsConstBase(base, xIndexBitsRev)

	return f.gl.Mul(g, product)
}

// precomputeAlphaPowers returns 1, alpha, ..., alpha^maxExponent.
// The caller must supply a canonical Goldilocks extension element.
func (f *Chip) precomputeAlphaPowers(alpha gl.QuadraticExtensionVariable, maxExponent int) []gl.QuadraticExtensionVariable {
	powers := make([]gl.QuadraticExtensionVariable, maxExponent+1)
	powers[0] = gl.OneExtension()
	if maxExponent > 0 {
		// Challenge values are normally already canonical; enforce the
		// precondition here as well before they become shared powers.
		f.gl.RangeCheckQE(alpha)
		powers[1] = alpha
	}
	for i := 2; i <= maxExponent; i++ {
		powers[i] = f.gl.MulExtension(powers[i-1], alpha)
	}
	return powers
}

// reduceBaseWithPowers evaluates sum evals[i]*powers[i], reducing each
// block of at most 8192 products. Each scalar and power coefficient is
// canonical; each product is <p^2 and the partial sum is <2^13*p^2+p.
// Consequently the quotient is <2^77, and a bound of 80 bits suffices.
func (f *Chip) reduceBaseWithPowers(evals []gl.Variable, powers []gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	if len(powers) < len(evals) {
		panic("not enough alpha powers")
	}
	const blockSize = 8192
	accum := gl.ZeroExtension()
	pending := 0
	for i, eval := range evals {
		f.gl.RangeCheck(eval)
		accum[0] = f.gl.MulAddNoReduce(eval, powers[i][0], accum[0])
		accum[1] = f.gl.MulAddNoReduce(eval, powers[i][1], accum[1])
		pending++
		if pending == blockSize {
			accum = gl.NewQuadraticExtensionVariable(f.gl.ReduceWithMaxBits(accum[0], 80), f.gl.ReduceWithMaxBits(accum[1], 80))
			pending = 0
		}
	}
	if pending != 0 {
		accum = gl.NewQuadraticExtensionVariable(f.gl.ReduceWithMaxBits(accum[0], 80), f.gl.ReduceWithMaxBits(accum[1], 80))
	}
	return accum
}

func (f *Chip) friCombineInitial(
	instance InstanceInfo,
	proof variables.FriInitialTreeProof,
	subgroupX_QE gl.QuadraticExtensionVariable,
	precomputedReducedEval []gl.QuadraticExtensionVariable,
	precomputedAlphaPowers []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	sum := gl.ZeroExtension()

	if len(instance.Batches) != len(precomputedReducedEval) {
		panic("len(openings) != len(precomputedReducedEval)")
	}

	for i := 0; i < len(instance.Batches); i++ {
		batch := instance.Batches[i]
		reducedOpenings := precomputedReducedEval[i]

		point := batch.Point
		evals := make([]gl.Variable, 0, len(batch.Polynomials))
		for _, polynomial := range batch.Polynomials {
			evals = append(evals, proof.EvalsProofs[polynomial.OracleIndex].Elements[polynomial.PolynomialInfo])
		}
		if len(precomputedAlphaPowers) <= len(evals) {
			panic("not enough alpha powers")
		}
		reducedEvals := f.reduceBaseWithPowers(evals, precomputedAlphaPowers)
		numerator := f.gl.SubExtensionNoReduce(reducedEvals, reducedOpenings)
		denominator := f.gl.SubExtension(subgroupX_QE, point)
		sum = f.gl.MulExtension(precomputedAlphaPowers[len(evals)], sum)
		inv, hasInv := f.gl.InverseExtension(denominator)
		f.api.AssertIsEqual(hasInv, frontend.Variable(1))
		sum = f.gl.MulAddExtension(
			numerator,
			inv,
			sum,
		)
	}

	return sum
}

func (f *Chip) finalPolyEval(finalPoly variables.PolynomialCoeffs, point gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	ret := gl.ZeroExtension()
	for i := len(finalPoly.Coeffs) - 1; i >= 0; i-- {
		ret = f.gl.MulAddExtensionCanonical(ret, point, finalPoly.Coeffs[i])
	}
	return ret
}

func (f *Chip) interpolate(
	x gl.QuadraticExtensionVariable,
	xPoints []gl.QuadraticExtensionVariable,
	yPoints []gl.QuadraticExtensionVariable,
	barycentricWeights []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	if len(xPoints) != len(yPoints) || len(xPoints) != len(barycentricWeights) {
		panic("length of xPoints, yPoints, and barycentricWeights are inconsistent")
	}
	// Each y value comes from the proof. Constrain it even when the
	// verifier-wide rangeCheckProof call is disabled.
	for _, y := range yPoints {
		f.gl.RangeCheckQE(y)
	}
	// Prefix products P[i] = product_{j<i} (x-x_j).
	n := len(xPoints)
	differences := make([]gl.QuadraticExtensionVariable, n)
	prefix := make([]gl.QuadraticExtensionVariable, n+1)
	prefix[0] = gl.OneExtension()
	for i := range xPoints {
		differences[i] = f.gl.SubExtension(x, xPoints[i])
		prefix[i+1] = f.gl.MulExtension(prefix[i], differences[i])
	}
	// The previous implementation's division enforces every denominator to
	// be nonzero, including when x equals an interpolation point.
	f.api.AssertIsEqual(f.gl.IsZero(prefix[n]), 0)
	suffix := gl.OneExtension()
	sum := gl.ZeroExtension()
	for i := n - 1; i >= 0; i-- {
		others := f.gl.MulExtension(prefix[i], suffix)
		weighted := f.gl.MulExtension(yPoints[i], barycentricWeights[i])
		sum = f.gl.MulAddExtensionCanonical(weighted, others, sum)
		if i != 0 {
			suffix = f.gl.MulExtension(suffix, differences[i])
		}
	}
	return sum
}

func (f *Chip) computeEvaluation(
	x gl.Variable,
	xIndexWithinCosetBits []frontend.Variable,
	arityBits uint64,
	evals []gl.QuadraticExtensionVariable,
	beta gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	arity := 1 << arityBits
	if (len(evals)) != arity {
		panic("len(evals) != arity")
	}
	if arityBits > 8 {
		panic("currently assuming that arityBits is <= 8")
	}

	g := gl.PrimitiveRootOfUnity(arityBits)
	gInv := goldilocks.NewElement(0)
	gInv.Exp(g, big.NewInt(int64(arity-1)))

	// The evaluation vector needs to be reordered first.  Permute the evals array such that each
	// element's new index is the bit reverse of it's original index.
	// OPTIMIZE - Since the size of the evals array should be constant (e.g. 2^arityBits),
	//        we can just hard code the permutation.
	permutedEvals := make([]gl.QuadraticExtensionVariable, len(evals))
	for i := uint8(0); i <= uint8(len(evals)-1); i++ {
		newIndex := bits.Reverse8(i) >> (8 - arityBits)
		permutedEvals[newIndex] = evals[i]
	}

	// Want `g^(arity - rev_x_index_within_coset)` as in the out-of-circuit version. Compute it
	// as `(g^-1)^rev_x_index_within_coset`.
	revXIndexWithinCosetBits := make([]frontend.Variable, len(xIndexWithinCosetBits))
	for i := 0; i < len(xIndexWithinCosetBits); i++ {
		revXIndexWithinCosetBits[len(xIndexWithinCosetBits)-1-i] = xIndexWithinCosetBits[i]
	}
	start := f.expFromBitsConstBase(gInv, revXIndexWithinCosetBits)
	cosetStart := f.gl.Mul(start, x)

	xPoints := make([]gl.QuadraticExtensionVariable, len(evals))
	yPoints := permutedEvals

	// OPTIMIZE: Make g_F a constant
	g_F := gl.NewVariable(g.Uint64()).ToQuadraticExtension()
	xPoints[0] = gl.QuadraticExtensionVariable{cosetStart, gl.Zero()}
	for i := 1; i < len(evals); i++ {
		xPoints[i] = f.gl.MulExtension(xPoints[i-1], g_F)
	}

	// For n=1 there are no differences in the product, so its weight is 1
	// even when the coset starts at zero.
	barycentricWeights := make([]gl.QuadraticExtensionVariable, len(xPoints))
	if arity == 1 {
		barycentricWeights[0] = gl.OneExtension()
	} else {
		// x_i = s*g^i with g a primitive n-th root and s != 0. The
		// derivative of X^n-s^n at x_i is n*s^n/x_i, hence the
		// barycentric weight is x_i/(n*s^n).
		inverseStart, hasInverse := f.gl.Inverse(cosetStart)
		f.api.AssertIsEqual(hasInverse, 1)
		inverseStartPow := inverseStart
		for i := uint64(0); i < arityBits; i++ {
			inverseStartPow = f.gl.Mul(inverseStartPow, inverseStartPow)
		}
		nField := goldilocks.NewElement(uint64(arity))
		nInverse := goldilocks.NewElement(0)
		nInverse.Inverse(&nField)
		factor := f.gl.Mul(inverseStartPow, gl.NewVariable(nInverse.Uint64()))
		for i := range xPoints {
			barycentricWeights[i] = f.gl.Mul(xPoints[i][0], factor).ToQuadraticExtension()
		}
	}

	return f.interpolate(beta, xPoints, yPoints, barycentricWeights)
}

func (f *Chip) verifyQueryRound(
	instance InstanceInfo,
	challenges *variables.FriChallenges,
	precomputedReducedEval []gl.QuadraticExtensionVariable,
	precomputedAlphaPowers []gl.QuadraticExtensionVariable,
	initialMerkleCaps []variables.FriMerkleCap,
	proof *variables.FriProof,
	xIndex gl.Variable,
	n uint64,
	nLog uint64,
	roundProof *variables.FriQueryRound,
) {
	// Note assertNoncanonicalIndicesOK does not add any constraints, it's a sanity check on the config
	assertNoncanonicalIndicesOK(*f.friParams)

	xIndex = f.gl.Reduce(xIndex)
	xIndexBits := f.api.ToBinary(xIndex.Limb, 64)[0 : f.friParams.DegreeBits+f.friParams.Config.RateBits]
	capIndexBits := xIndexBits[len(xIndexBits)-int(f.friParams.Config.CapHeight):]
	f.verifyInitialProof(xIndexBits, &roundProof.InitialTreesProof, initialMerkleCaps, capIndexBits)

	subgroupX := f.calculateSubgroupX(
		xIndexBits,
		nLog,
	)
	subgroupX_QE := subgroupX.ToQuadraticExtension()

	oldEval := f.friCombineInitial(
		instance,
		roundProof.InitialTreesProof,
		subgroupX_QE,
		precomputedReducedEval,
		precomputedAlphaPowers,
	)

	for i, arityBits := range f.friParams.ReductionArityBits {
		evals := roundProof.Steps[i].Evals

		cosetIndexBits := xIndexBits[arityBits:]
		xIndexWithinCosetBits := xIndexBits[:arityBits]

		// Assumes that the arity bits will be 4.  That means that the range of
		// xIndexWithCoset is [0,2^4-1].  This is based on plonky2's circuit recursive
		// config:  https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/plonk/circuit_data.rs#L63
		// Will use a two levels tree of 4-selector gadgets.
		if arityBits != 4 {
			panic("assuming arity bits is 4")
		}

		const NUM_LEAF_LOOKUPS = 4
		var leafLookups [NUM_LEAF_LOOKUPS]gl.QuadraticExtensionVariable
		// First create the "leaf" lookup2 circuits
		// The will use the least significant bits of the xIndexWithCosetBits array
		for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
			leafLookups[i] = f.gl.Lookup2(
				xIndexWithinCosetBits[0],
				xIndexWithinCosetBits[1],
				evals[i*NUM_LEAF_LOOKUPS],
				evals[i*NUM_LEAF_LOOKUPS+1],
				evals[i*NUM_LEAF_LOOKUPS+2],
				evals[i*NUM_LEAF_LOOKUPS+3],
			)
		}

		// Use the most 2 significant bits of the xIndexWithCosetBits array for the "root" lookup
		newEval := f.gl.Lookup2(
			xIndexWithinCosetBits[2],
			xIndexWithinCosetBits[3],
			leafLookups[0],
			leafLookups[1],
			leafLookups[2],
			leafLookups[3],
		)
		f.gl.AssertIsEqual(newEval[0], oldEval[0])
		f.gl.AssertIsEqual(newEval[1], oldEval[1])

		oldEval = f.computeEvaluation(
			subgroupX,
			xIndexWithinCosetBits,
			arityBits,
			evals,
			challenges.FriBetas[i],
		)

		// Convert evals (array of QE) to fields by taking their 0th degree coefficients
		fieldEvals := make([]gl.Variable, 0, 2*len(evals))
		for j := 0; j < len(evals); j++ {
			fieldEvals = append(fieldEvals, evals[j][0])
			fieldEvals = append(fieldEvals, evals[j][1])
		}

		f.verifyMerkleProofToCapWithCapIndex(
			fieldEvals,
			cosetIndexBits,
			capIndexBits,
			proof.CommitPhaseMerkleCaps[i],
			&roundProof.Steps[i].MerkleProof,
		)

		// Update the point x to x^arity.
		for j := uint64(0); j < arityBits; j++ {
			subgroupX = f.gl.Mul(subgroupX, subgroupX)
		}

		xIndexBits = cosetIndexBits
	}

	subgroupX_QE = subgroupX.ToQuadraticExtension()
	finalPolyEval := f.finalPolyEval(proof.FinalPoly, subgroupX_QE)

	f.gl.AssertIsEqual(oldEval[0], finalPolyEval[0])
	f.gl.AssertIsEqual(oldEval[1], finalPolyEval[1])
}

func (f *Chip) VerifyFriProof(
	instance InstanceInfo,
	openings Openings,
	friChallenges *variables.FriChallenges,
	initialMerkleCaps []variables.FriMerkleCap,
	friProof *variables.FriProof,
) {
	// Not adding any constraints but a sanity check on the proof shape matching the friParams (constant).
	validateFriProofShape(friProof, instance, f.friParams)

	// Check POW
	f.assertLeadingZeros(friChallenges.FriPowResponse, f.friParams.Config)

	// Check that parameters are coherent. Not adding any constraints but a sanity check
	// on the proof shape matching the friParams.
	if int(f.friParams.Config.NumQueryRounds) != len(friProof.QueryRoundProofs) {
		panic("Number of query rounds does not match config.")
	}

	precomputedReducedEvals := f.fromOpeningsAndAlpha(&openings, friChallenges.FriAlpha)

	// Size of the LDE domain.
	nLog := f.friParams.DegreeBits + f.friParams.Config.RateBits
	n := uint64(math.Pow(2, float64(nLog)))

	if len(friChallenges.FriQueryIndices) != len(friProof.QueryRoundProofs) {
		panic(fmt.Sprintf(
			"Number of query indices (%d) should equal number of query round proofs (%d)",
			len(friChallenges.FriQueryIndices),
			len(friProof.QueryRoundProofs),
		))
	}

	// The alpha and batch polynomial counts are shared by every query round.
	// Avoid introducing unused constraints when there are no query rounds.
	var alphaPowers []gl.QuadraticExtensionVariable
	if len(friChallenges.FriQueryIndices) != 0 {
		maxExponent := 0
		for _, batch := range instance.Batches {
			if len(batch.Polynomials) > maxExponent {
				maxExponent = len(batch.Polynomials)
			}
		}
		alphaPowers = f.precomputeAlphaPowers(friChallenges.FriAlpha, maxExponent)
	}

	for idx, xIndex := range friChallenges.FriQueryIndices {

		roundProof := friProof.QueryRoundProofs[idx]

		f.verifyQueryRound(
			instance,
			friChallenges,
			precomputedReducedEvals,
			alphaPowers,
			initialMerkleCaps,
			friProof,
			xIndex,
			n,
			nLog,
			&roundProof,
		)
	}
}
