// Command drandverify verifies one retained drand HTTP response against its
// chain information. It deliberately performs no network requests: callers
// must retain the exact chain-info and beacon bytes used as evidence.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/common/chain"
	"github.com/drand/drand/v2/crypto"
)

const (
	schemaVersion     = "ravage.paired-xben.drand-verification.v1"
	selfSchemaVersion = "ravage.paired-xben.drand-verifier-self.v1"
	maxInputBytes     = 256 * 1024
)

// sourceBundleSHA256 is injected by the documented build command. A binary
// without this binding is rejected by the Python protocol before commitment.
var sourceBundleSHA256 = "unbound"

type beaconSource struct {
	Round             uint64 `json:"round"`
	Signature         string `json:"signature"`
	PreviousSignature string `json:"previous_signature"`
	Randomness        string `json:"randomness"`
}

type receipt struct {
	SchemaVersion   string `json:"schema_version"`
	Verified        bool   `json:"verified"`
	LibraryModule   string `json:"library_module"`
	LibraryVersion  string `json:"library_version"`
	ChainHash       string `json:"chain_hash"`
	Round           uint64 `json:"round"`
	Scheme          string `json:"scheme"`
	Randomness      string `json:"randomness"`
	ChainInfoSHA256 string `json:"chain_info_sha256"`
	BeaconSHA256    string `json:"beacon_sha256"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

func main() {
	selfInfo := flag.Bool("self-info", false, "print machine-readable verifier identity")
	chainInfoPath := flag.String("chain-info", "", "path to retained drand chain-info JSON")
	beaconPath := flag.String("beacon", "", "path to retained drand beacon JSON")
	expectedChainHash := flag.String("expected-chain-hash", "", "committed chain hash")
	expectedRound := flag.String("expected-round", "", "committed round")
	expectedGenesis := flag.String("expected-genesis-time", "", "committed genesis Unix time")
	expectedPeriod := flag.String("expected-period-seconds", "", "committed period in seconds")
	flag.Parse()
	if *selfInfo {
		encoder := json.NewEncoder(os.Stdout)
		if err := encoder.Encode(map[string]any{
			"schema_version":       selfSchemaVersion,
			"library_module":       "github.com/drand/drand/v2",
			"library_version":      "v2.1.6",
			"source_bundle_sha256": sourceBundleSHA256,
		}); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "encode self info: %v\n", err)
			os.Exit(2)
		}
		return
	}

	result, err := verify(
		*chainInfoPath,
		*beaconPath,
		*expectedChainHash,
		*expectedRound,
		*expectedGenesis,
		*expectedPeriod,
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "drand verification failed: %v\n", err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "encode receipt: %v\n", err)
		os.Exit(2)
	}
}

func verify(chainInfoPath, beaconPath, chainHash, roundText, genesisText, periodText string) (*receipt, error) {
	if chainInfoPath == "" || beaconPath == "" {
		return nil, errors.New("both input paths are required")
	}
	expectedHash, err := decodeFixedHex(chainHash, 32, "expected chain hash")
	if err != nil {
		return nil, err
	}
	round, err := parsePositiveUint(roundText, "expected round")
	if err != nil {
		return nil, err
	}
	genesis, err := parsePositiveUint(genesisText, "expected genesis time")
	if err != nil {
		return nil, err
	}
	period, err := parsePositiveUint(periodText, "expected period")
	if err != nil {
		return nil, err
	}

	chainBytes, err := readBounded(chainInfoPath)
	if err != nil {
		return nil, fmt.Errorf("read chain info: %w", err)
	}
	var info chain.Info
	if err := json.Unmarshal(chainBytes, &info); err != nil {
		return nil, fmt.Errorf("decode or authenticate chain info: %w", err)
	}
	if !bytes.Equal(info.Hash(), expectedHash) {
		return nil, errors.New("chain info hash differs from committed chain hash")
	}
	if info.GenesisTime != int64(genesis) || uint64(info.Period.Seconds()) != period {
		return nil, errors.New("chain timing differs from commitment")
	}

	beaconBytes, err := readBounded(beaconPath)
	if err != nil {
		return nil, fmt.Errorf("read beacon: %w", err)
	}
	var source beaconSource
	decoder := json.NewDecoder(bytes.NewReader(beaconBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("decode beacon: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	if source.Round != round {
		return nil, errors.New("beacon round differs from commitment")
	}
	signature, err := decodeHex(source.Signature, "signature")
	if err != nil {
		return nil, err
	}
	previousSignature, err := decodeHex(source.PreviousSignature, "previous signature")
	if err != nil {
		return nil, err
	}
	randomness, err := decodeFixedHex(source.Randomness, 32, "randomness")
	if err != nil {
		return nil, err
	}
	derived := crypto.RandomnessFromSignature(signature)
	if !bytes.Equal(randomness, derived) {
		return nil, errors.New("randomness is not SHA-256 of the signature")
	}

	scheme, err := crypto.GetSchemeByID(info.Scheme)
	if err != nil {
		return nil, fmt.Errorf("load advertised drand scheme: %w", err)
	}
	beacon := &common.Beacon{
		PreviousSig: common.HexBytes(previousSignature),
		Round:       source.Round,
		Signature:   common.HexBytes(signature),
	}
	if err := scheme.VerifyBeacon(beacon, info.PublicKey); err != nil {
		return nil, fmt.Errorf("verify BLS beacon signature: %w", err)
	}
	publicKey, err := info.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	chainSum := sha256.Sum256(chainBytes)
	beaconSum := sha256.Sum256(beaconBytes)
	publicKeySum := sha256.Sum256(publicKey)
	return &receipt{
		SchemaVersion:   schemaVersion,
		Verified:        true,
		LibraryModule:   "github.com/drand/drand/v2",
		LibraryVersion:  "v2.1.6",
		ChainHash:       chainHash,
		Round:           round,
		Scheme:          info.Scheme,
		Randomness:      source.Randomness,
		ChainInfoSHA256: "sha256:" + hex.EncodeToString(chainSum[:]),
		BeaconSHA256:    "sha256:" + hex.EncodeToString(beaconSum[:]),
		PublicKeySHA256: "sha256:" + hex.EncodeToString(publicKeySum[:]),
	}, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limited := io.LimitReader(file, maxInputBytes+1)
	value, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(value) > maxInputBytes {
		return nil, errors.New("input exceeds byte limit")
	}
	return value, nil
}

func decodeHex(value, label string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is empty", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hexadecimal: %w", label, err)
	}
	return decoded, nil
}

func decodeFixedHex(value string, size int, label string) ([]byte, error) {
	decoded, err := decodeHex(value, label)
	if err != nil {
		return nil, err
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("%s must be %d bytes", label, size)
	}
	return decoded, nil
}

func parsePositiveUint(value, label string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a positive integer", label)
	}
	return parsed, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		return errors.New("beacon contains trailing JSON data")
	}
	return nil
}
