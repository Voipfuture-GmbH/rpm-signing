package common

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func randomFile(t *testing.T) (string, error) {
	dir := t.TempDir()

	if fileName, err := RandomString(20, "abcdefghijklmnopqrstuvwxyz"); err == nil {
		return filepath.Join(dir, fileName), nil
	} else {
		return "", err
	}
}

func parseRPM(fileName string, validatePayloadMd5 bool) (RpmFile, ReaderWithOffset, error) {
	var err error
	var file *os.File
	if file, err = os.Open(fileName); err != nil {
		return RpmFile{}, nil, fmt.Errorf("failed to open %v - %w", fileName, err)
	}
	// NOTE: File must be closed by caller

	inputReader := NewIOReaderWithOffset(file)
	// NOTE: ParseRPMFromReader WITHOUT validation (validatePayloadMd5 == false)
	//       will read up to the beginning of the RPM payload so the returned
	//       ReaderWithOffset is in fact the payload reader
	rpmFile, err := ParseRPMFromReader(inputReader, validatePayloadMd5)
	if err != nil {
		_ = file.Close()
		return RpmFile{}, nil, err
	}
	return rpmFile, inputReader, nil
}

func TestSignRpm(t *testing.T) {

	const fileName = "testdata/my-payload-package-1.0-1.noarch.rpm"
	const privKey = "testdata/my-signing-key.priv.gpg.asc"
	var err error

	outputName, err := randomFile(t)
	if err != nil {
		t.Fatal(err)
	}

	var rpmFile RpmFile
	// NOTE: It's important to NOT perform payload validation here because otherwise
	//       the returned reader will not be at the start of the payload but at the end of the file
	rpmFile, payloadReader, err := parseRPM(fileName, false)
	if err != nil {
		t.Fatalf("Failed to parse %v - %v", fileName, err)
	}

	privateKey, err := LoadPrivateKeyFromFile(privKey, []byte{})
	if err != nil {
		t.Fatalf("Failed to load private key - %v", err)
	}
	if err = SignRpm(&rpmFile, privateKey); err != nil {
		CloseQuietly(payloadReader)
		t.Fatalf("Failed to sign %v - %v", fileName, err)
	}

	err = rpmFile.WriteToFile(outputName, payloadReader)
	CloseQuietly(payloadReader)
	if err != nil {
		t.Fatalf("Failed open output file %v - %v", outputName, err)
	}

	// verify by parsing signed output again
	_, payloadReader, err = parseRPM(outputName, true)
	if err != nil {
		t.Fatalf("round-trip failed - %v", err)
	}
	CloseQuietly(payloadReader)
}

const (
	testRpm    = "testdata/my-payload-package-1.0-1.noarch.rpm"
	rsaPrivKey = "testdata/my-signing-key.priv.gpg.asc"
	rsaPubKey  = "testdata/my-signing-key.pub.gpg.asc"
	dsaPrivKey = "testdata/my-dsa-signing-key.priv.gpg.asc"
	dsaPubKey  = "testdata/my-dsa-signing-key.pub.gpg.asc"
)

// signTestRpm signs the test RPM with the given private key file and returns the
// signed file, parsed back from the bytes that were actually written.
func signTestRpm(privateKeyFile string, t *testing.T) RpmFile {

	t.Helper()

	rpmFile, payloadReader, err := parseRPM(testRpm, false)
	if err != nil {
		t.Fatalf("Failed to parse %s - %v", testRpm, err)
	}
	defer CloseQuietly(payloadReader)

	privateKey, err := LoadPrivateKeyFromFile(privateKeyFile, []byte{})
	if err != nil {
		t.Fatalf("Failed to load private key %s - %v", privateKeyFile, err)
	}
	if err = SignRpm(&rpmFile, privateKey); err != nil {
		t.Fatalf("Failed to sign with %s - %v", privateKeyFile, err)
	}
	assertHeaderConsistent(&rpmFile.SignatureHeader, "signed with "+privateKeyFile, t)

	return assertRoundTrips(rpmFile, payloadReader, "signed with "+privateKeyFile, t)
}

// assertV4SignatureValid runs the V4 verification against the given public key file
// and fails unless the outcome is the expected one.
func assertV4SignatureValid(rpmFile RpmFile, publicKeyFile string, expectValid bool, label string, t *testing.T) {

	t.Helper()

	publicKeys, err := LoadPublicKeys([]string{publicKeyFile})
	if err != nil {
		t.Fatalf("%s: failed to load public key %s - %v", label, publicKeyFile, err)
	}
	// a V4 signature covers the main header only, so no payload reader is needed
	err = NewSignatureVerifier(rpmFile, nil, publicKeys).VerifyV4Signature()
	if expectValid && err != nil {
		t.Errorf("%s: signature should have verified against %s but did not - %v", label, publicKeyFile, err)
	}
	if !expectValid && err == nil {
		t.Errorf("%s: signature should NOT have verified against %s but did", label, publicKeyFile)
	}
}

// TestSignRpmWithDsaKey covers signing with a DSA key, which has to end up in
// RPMSIGTAG_DSA (tag 267) rather than the RPMSIGTAG_RSA (tag 268) an RSA key uses.
func TestSignRpmWithDsaKey(t *testing.T) {

	signed := signTestRpm(dsaPrivKey, t)

	if signed.SignatureHeader.FindIndexEntry(SigTagDSAHeader) == nil {
		t.Error("DSA signed RPM has no DSAHEADER (tag 267) entry")
	}
	if signed.SignatureHeader.FindIndexEntry(SigTagRSAHeader) != nil {
		t.Error("DSA signed RPM must not have an RSAHEADER (tag 268) entry")
	}
	if !signed.GetSignatureVersions().Contains(SIGNATURE_VERSION_V4) {
		t.Error("DSA signed RPM is not recognized as carrying a V4 signature")
	}

	assertV4SignatureValid(signed, dsaPubKey, true, "DSA signed", t)
	assertV4SignatureValid(signed, rsaPubKey, false, "DSA signed", t)
}

// TestSignRpmWithRsaKey is the RSA counterpart of TestSignRpmWithDsaKey and guards
// against the DSA support regressing the RSA case.
func TestSignRpmWithRsaKey(t *testing.T) {

	signed := signTestRpm(rsaPrivKey, t)

	if signed.SignatureHeader.FindIndexEntry(SigTagRSAHeader) == nil {
		t.Error("RSA signed RPM has no RSAHEADER (tag 268) entry")
	}
	if signed.SignatureHeader.FindIndexEntry(SigTagDSAHeader) != nil {
		t.Error("RSA signed RPM must not have a DSAHEADER (tag 267) entry")
	}

	assertV4SignatureValid(signed, rsaPubKey, true, "RSA signed", t)
	assertV4SignatureValid(signed, dsaPubKey, false, "RSA signed", t)
}

// TestSignRpmReplacesTagOfOtherKeyType covers re-signing an already signed RPM with a
// key of the other type: the signature tag belonging to the previous key type has to
// be removed, otherwise the RPM would carry a signature no one can verify anymore.
func TestSignRpmReplacesTagOfOtherKeyType(t *testing.T) {

	for _, testCase := range []struct {
		label      string
		firstKey   string
		secondKey  string
		wantTag    TagValue
		removedTag TagValue
	}{
		{"RSA then DSA", rsaPrivKey, dsaPrivKey, SigTagDSAHeader, SigTagRSAHeader},
		{"DSA then RSA", dsaPrivKey, rsaPrivKey, SigTagRSAHeader, SigTagDSAHeader},
	} {
		t.Run(testCase.label, func(t *testing.T) {

			rpmFile, payloadReader, err := parseRPM(testRpm, false)
			if err != nil {
				t.Fatalf("Failed to parse %s - %v", testRpm, err)
			}
			defer CloseQuietly(payloadReader)

			for _, keyFile := range []string{testCase.firstKey, testCase.secondKey} {
				privateKey, err := LoadPrivateKeyFromFile(keyFile, []byte{})
				if err != nil {
					t.Fatalf("Failed to load private key %s - %v", keyFile, err)
				}
				if err = SignRpm(&rpmFile, privateKey); err != nil {
					t.Fatalf("Failed to sign with %s - %v", keyFile, err)
				}
				assertHeaderConsistent(&rpmFile.SignatureHeader, testCase.label, t)
			}

			if rpmFile.SignatureHeader.FindIndexEntry(testCase.wantTag) == nil {
				t.Errorf("%s: signature tag %d of the second key is missing", testCase.label, testCase.wantTag.ID())
			}
			if rpmFile.SignatureHeader.FindIndexEntry(testCase.removedTag) != nil {
				t.Errorf("%s: signature tag %d of the first key was not removed", testCase.label, testCase.removedTag.ID())
			}
			assertRoundTrips(rpmFile, payloadReader, testCase.label, t)
		})
	}
}

// TestGetKeyType checks that the key types signing branches on are told apart, as
// SignRpm() picks the signature header tag from them.
func TestGetKeyType(t *testing.T) {

	for _, testCase := range []struct {
		keyFile string
		want    KeyType
	}{
		{rsaPrivKey, KEY_TYPE_RSA},
		{dsaPrivKey, KEY_TYPE_DSA},
	} {
		privateKey, err := LoadPrivateKeyFromFile(testCase.keyFile, []byte{})
		if err != nil {
			t.Fatalf("Failed to load private key %s - %v", testCase.keyFile, err)
		}
		if got := GetKeyType(privateKey); got != testCase.want {
			t.Errorf("%s: expected key type %v, got %v", testCase.keyFile, testCase.want, got)
		}
	}
	if KEY_TYPE_DSA == KEY_TYPE_OTHER {
		t.Error("KEY_TYPE_DSA and KEY_TYPE_OTHER must be distinguishable")
	}
}
