package worker

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/zilong-dai/gnark/backend/groth16/bn254/mpcsetup"
)

// ReadPhase1 reads the required power-of-two prefix of a snarkjs BN254 ptau.
// It checks the file layout, but does not validate individual points or the ceremony transcript.
func ReadPhase1(path string, power uint) (*mpcsetup.Phase1, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	var magic [4]byte
	if _, err = io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != "ptau" { return nil, fmt.Errorf("invalid ptau header") }
	var version, count uint32
	if binary.Read(f, binary.LittleEndian, &version) != nil || binary.Read(f, binary.LittleEndian, &count) != nil || version != 1 || count > 64 { return nil, fmt.Errorf("invalid ptau version or section count") }
	type section struct { offset int64; size uint64 }
	sections := map[uint32]section{}
	stat, err := f.Stat(); if err != nil { return nil, err }
	for i := uint32(0); i < count; i++ {
		var id uint32; var size uint64
		if binary.Read(f, binary.LittleEndian, &id) != nil || binary.Read(f, binary.LittleEndian, &size) != nil { return nil, fmt.Errorf("invalid section header") }
		pos, e := f.Seek(0, io.SeekCurrent); if e != nil || size > uint64(stat.Size()-pos) { return nil, fmt.Errorf("truncated section %d", id) }
		if _, exists := sections[id]; exists { return nil, fmt.Errorf("duplicate section %d", id) }
		sections[id] = section{pos, size}
		if _, err = f.Seek(int64(size), io.SeekCurrent); err != nil { return nil, err }
	}
	h, ok := sections[1]; if !ok || h.size != 44 { return nil, fmt.Errorf("invalid ptau curve header") }
	if _, err = f.Seek(h.offset, io.SeekStart); err != nil { return nil, err }
	var width, filePower, ceremonyPower uint32
	var modulus [32]byte
	if binary.Read(f, binary.LittleEndian, &width) != nil { return nil, fmt.Errorf("invalid field width") }
	if _, err = io.ReadFull(f, modulus[:]); err != nil { return nil, err }
	if binary.Read(f, binary.LittleEndian, &filePower) != nil || binary.Read(f, binary.LittleEndian, &ceremonyPower) != nil { return nil, fmt.Errorf("invalid power") }
	for i := 0; i < 16; i++ { modulus[i], modulus[31-i] = modulus[31-i], modulus[i] }
	if width != 32 || new(big.Int).SetBytes(modulus[:]).Cmp(fp.Modulus()) != 0 || filePower > 28 || ceremonyPower < filePower || power > uint(filePower) || power == 0 { return nil, fmt.Errorf("unsupported curve or power") }
	n := 1 << power
	var result mpcsetup.Phase1
	result.Parameters.G1.Tau = make([]curve.G1Affine, 2*n-1)
	result.Parameters.G2.Tau = make([]curve.G2Affine, n)
	result.Parameters.G1.AlphaTau = make([]curve.G1Affine, n)
	result.Parameters.G1.BetaTau = make([]curve.G1Affine, n)
	readField := func(r io.Reader, x *fp.Element) error {
		var b [32]byte; if _, e := io.ReadFull(r, b[:]); e != nil { return e }
		for i := range x { x[i] = binary.LittleEndian.Uint64(b[i*8:]) }
		return nil
	}
	readG1 := func(r io.Reader, p *curve.G1Affine) error { if e := readField(r, &p.X); e != nil { return e }; if e := readField(r, &p.Y); e != nil { return e }; return nil }
	readG2 := func(r io.Reader, p *curve.G2Affine) error { for _, x := range []*fp.Element{&p.X.A0, &p.X.A1, &p.Y.A0, &p.Y.A1} { if e := readField(r, x); e != nil { return e } }; return nil }
	full := uint64(1) << filePower
	for id := uint32(2); id <= 6; id++ {
		s, ok := sections[id]; if !ok { return nil, fmt.Errorf("missing section %d", id) }
		var expected uint64; switch id { case 2: expected = (2*full-1)*64; case 3: expected = full*128; case 4,5: expected = full*64; case 6: expected = 128 }
		if s.size != expected { return nil, fmt.Errorf("invalid section %d size", id) }
		if _, err = f.Seek(s.offset, io.SeekStart); err != nil { return nil, err }
		started := time.Now()
		fmt.Printf("[phase1] reading section %d: power=%d\n", id, power)
		var e error
		switch id { case 2: for i := range result.Parameters.G1.Tau { if e = readG1(f, &result.Parameters.G1.Tau[i]); e != nil { break } }; case 3: for i := range result.Parameters.G2.Tau { if e = readG2(f, &result.Parameters.G2.Tau[i]); e != nil { break } }; case 4: for i := range result.Parameters.G1.AlphaTau { if e = readG1(f, &result.Parameters.G1.AlphaTau[i]); e != nil { break } }; case 5: for i := range result.Parameters.G1.BetaTau { if e = readG1(f, &result.Parameters.G1.BetaTau[i]); e != nil { break } }; case 6: e = readG2(f, &result.Parameters.G2.Beta) }
		if e != nil { return nil, fmt.Errorf("section %d: %w", id, e) }
		fmt.Printf("[phase1] section %d complete in %s\n", id, time.Since(started))
	}
	return &result, nil
}
