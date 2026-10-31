package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testChainInfo = `{"public_key":"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31","period":30,"genesis_time":1595431050,"hash":"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce","groupHash":"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a","schemeID":"pedersen-bls-chained","metadata":{"beaconID":"default"}}`

const testBeacon = `{"round":1000,"signature":"99bf96de133c3d3937293cfca10c8152b18ab2d034ccecf115658db324d2edc00a16a2044cd04a8a38e2a307e5ecff3511315be8d282079faf24098f283e0ed2c199663b334d2e84c55c032fe469b212c5c2087ebb83a5b25155c3283f5b79ac","previous_signature":"af0d93299a363735fe847f5ea241442c65843dc1bd3a7b79646b3b10072e908bf034d35cd69d378e3341f139100cd4cd03030399864ef8803a5a4f5e64fccc20bbae36d1ca22a6ddc43d2630c41105e90598fab11e5c7456df3925d4b577b113","randomness":"a40d3e0e7e3c71f28b7da2fd339f47f0bcf10910309f5253d7c323ec8cea3212"}`

func TestVerifyKnownMainnetBeacon(t *testing.T) {
	directory := t.TempDir()
	chainPath := filepath.Join(directory, "chain.json")
	beaconPath := filepath.Join(directory, "beacon.json")
	if err := os.WriteFile(chainPath, []byte(testChainInfo), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(beaconPath, []byte(testBeacon), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := verify(
		chainPath,
		beaconPath,
		"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
		"1000",
		"1595431050",
		"30",
	)
	if err != nil {
		t.Fatalf("known beacon did not verify: %v", err)
	}
	if !receipt.Verified || receipt.Randomness != "a40d3e0e7e3c71f28b7da2fd339f47f0bcf10910309f5253d7c323ec8cea3212" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	directory := t.TempDir()
	chainPath := filepath.Join(directory, "chain.json")
	beaconPath := filepath.Join(directory, "beacon.json")
	if err := os.WriteFile(chainPath, []byte(testChainInfo), 0o600); err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(testBeacon, "99bf96", "89bf96", 1)
	if err := os.WriteFile(beaconPath, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(
		chainPath,
		beaconPath,
		"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
		"1000",
		"1595431050",
		"30",
	); err == nil {
		t.Fatal("forged signature unexpectedly verified")
	}
}
