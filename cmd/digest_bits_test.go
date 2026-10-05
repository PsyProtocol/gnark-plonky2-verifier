package main

import (
	"fmt"
	"testing"

	"github.com/cf/gnark-plonky2-verifier/worker"
)

func TestDigestBitsResultOwnership(t *testing.T) {
	cases := []struct {
		name string
		operation func() (string, string, error)
		status uint32
	}{
		{"proof", func() (string, string, error) { return "{}", "{}", nil }, 0},
		{"setup", func() (string, string, error) { return "", "", nil }, 0},
		{"typed error", func() (string, string, error) {
			return "", "", &worker.DigestBitsError{Status: 2, Message: "identity mismatch"}
		}, 2},
		{"untyped error", func() (string, string, error) { return "", "", fmt.Errorf("failure") }, 5},
		{"panic", func() (string, string, error) { panic("failure") }, 5},
		{"nil panic", func() (string, string, error) { panic(nil) }, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := digestBitsResult(tc.operation)
			if result == nil {
				t.Fatal("null native result")
			}
			defer FreeGroth16DigestBitsResult(result)
			if uint32(result.status) != tc.status {
				t.Fatalf("status %d, want %d", result.status, tc.status)
			}
			if result.proof_json == nil || result.verifier_json == nil || result.error_message == nil {
				t.Fatal("result must own every string, including empty strings")
			}
			if tc.status != 0 && (*result.proof_json != 0 || *result.verifier_json != 0 || *result.error_message == 0) {
				t.Fatal("error result must contain only a nonempty diagnostic")
			}
		})
	}
}
