package common

import (
	"bytes"
	_ "crypto/sha256" // Registers SHA-256 with the crypto package
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func LoadPublicKeys(keyFiles []string) (openpgp.EntityList, error) {

	keyRing := make(openpgp.EntityList, 0)
	for _, keyFile := range keyFiles {
		file, err := os.Open(keyFile)
		if err != nil {
			return nil, err
		}
		keys, err := LoadPublicKey(file) // also closes key
		CloseQuietly(file)
		if err != nil {
			return nil, err
		}
		keyRing = append(keyRing, keys...)
	}
	return keyRing, nil
}

func LoadPublicKey(reader io.Reader) (openpgp.EntityList, error) {

	// ReadArmoredKeyRing parses the ASCII-armored public key block
	keyRing, err := openpgp.ReadArmoredKeyRing(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return keyRing, nil
}

type KeyType struct {
	id    uint8
	Label string
}

var (
	KEY_TYPE_RSA   = KeyType{1, "RSA"}
	KEY_TYPE_DSA   = KeyType{2, "DSA"}
	KEY_TYPE_OTHER = KeyType{3, "other key type"}
)

func GetKeyType(privateKey packet.PrivateKey) KeyType {
	switch privateKey.PubKeyAlgo {
	case packet.PubKeyAlgoRSA,
		packet.PubKeyAlgoRSASignOnly,
		packet.PubKeyAlgoRSAEncryptOnly:
		return KEY_TYPE_RSA
	case packet.PubKeyAlgoDSA:
		return KEY_TYPE_DSA
	default:

		return KEY_TYPE_OTHER
	}
}

func LoadPrivateKeyFromFile(privateKeyFilename string, passphrase []byte) (packet.PrivateKey, error) {
	// Load private key
	privateKeyFile, err := os.Open(privateKeyFilename)
	if err != nil {
		return packet.PrivateKey{}, fmt.Errorf("failed to load private key from %s : %v ", privateKeyFilename, err)
	}
	defer func() { _ = privateKeyFile.Close() }()

	privateKeyReader := NewSeekableReader(NewIOReaderWithOffset(privateKeyFile))
	defer CloseQuietly(privateKeyReader)

	privateKey, err := LoadPrivateKey(privateKeyReader, passphrase)
	if err != nil {
		return packet.PrivateKey{}, fmt.Errorf("failed to load private key from %s : %v ", privateKeyFilename, err)
	}
	return privateKey, nil
}

// LoadPrivateKey opens a file, parses the OpenPGP packet stream,
// and returns the primary RSA private key. If the key is encrypted,
// pass non-empty passphrase bytes.
func LoadPrivateKey(file SeekableReader, passphrase []byte) (packet.PrivateKey, error) {

	// 1. Detect if the file is ASCII-armored or raw binary
	var packetReader io.Reader
	armorBlock, err := armor.Decode(file)
	if err == nil {
		// It's ASCII armored (e.g., "-----BEGIN PGP PRIVATE KEY BLOCK-----")
		packetReader = armorBlock.Body
	} else {
		// Not armored or failed decode; seek back to start and read as raw binary packets
		if err := file.SeekRelativeToStart(0); err != nil {
			return packet.PrivateKey{}, fmt.Errorf("failed to seek key file: %w", err)
		}
		packetReader = file
	}

	// 2. Iterate through the packet stream to find the PrivateKey packet
	pkReader := packet.NewReader(packetReader)
	var privKey *packet.PrivateKey

	for {
		p, err := pkReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return packet.PrivateKey{}, fmt.Errorf("error reading packets: %w", err)
		}

		// Look for a PrivateKey packet (Tag 5 or Tag 7 for subkeys)
		if k, ok := p.(*packet.PrivateKey); ok {
			privKey = k
			break // Found primary private key
		}
	}

	if privKey == nil {
		return packet.PrivateKey{}, fmt.Errorf("no private key found")
	}

	// 3. Decrypt the key if it's protected with a passphrase
	if privKey.Encrypted {
		if len(passphrase) == 0 {
			return packet.PrivateKey{}, fmt.Errorf("private key is encrypted, but no passphrase was provided")
		}
		if err := privKey.Decrypt(passphrase); err != nil {
			return packet.PrivateKey{}, fmt.Errorf("failed to decrypt private key (wrong passphrase?): %w", err)
		}
	}

	return *privKey, nil
}

// VerifySignature verifies data against an OpenPGP signature packet.
//
// - pubKeyRing: The parsed public keyring (e.g., from /etc/pki/rpm-gpg/).
// - signedData: The exact raw, unpadded byte slice of the RPM Main Header.
// - signatureData: OpenPGP signature packet data. The raw bytes extracted from Tag 268/267 (or Base64-decoded from Tag 278).
//
// This function returns the identity of the key that signed it
func VerifySignature(pubKeyRing openpgp.EntityList, signedData []byte, signatureData []byte) (*openpgp.Entity, error) {

	// 1. Create io.Readers from your extracted byte slices
	headerReader := bytes.NewReader(signedData)
	sigReader := bytes.NewReader(signatureData)

	// 2. Check the detached signature
	// This handles parsing the OpenPGP packet, locating the matching public key,
	// hashing the header + trailer, and executing the RSA/DSA math.
	signerEntity, err := openpgp.CheckDetachedSignature(pubKeyRing, headerReader, sigReader, nil)
	if err != nil {
		return nil, fmt.Errorf("RPM signature verification failed: %w", err)
	}

	// 3. Success! The library returns the identity of the key that signed it.
	return signerEntity, nil
}

// SignDigest signs the provided digest using an RSA or DSA private key and returns
// the raw binary OpenPGP signature packet. The caller stores it in RPMSIGTAG_RSA
// (tag 268) for an RSA key and in RPMSIGTAG_DSA (tag 267) for a DSA key.
func SignDigest(digest hash.Hash, privKey *packet.PrivateKey) ([]byte, error) {

	// the accepted key types have to stay in sync with SignRpm(), which is what
	// picks the signature header tag the resulting packet ends up in
	if keyType := GetKeyType(*privKey); keyType != KEY_TYPE_RSA && keyType != KEY_TYPE_DSA {
		return nil, fmt.Errorf("signing requires an RSA or DSA key, got algorithm ID: %d", privKey.PubKeyAlgo)
	}

	/*
		When signing an RPM archive, the `Rsaheader` index entry (Tag 268, also known as `RPMSIGTAG_RSA`)
		is calculated by generating an OpenPGP RSA signature exclusively over the
		binary contents of the package's **Header section**.

		Unlike payload-inclusive signatures (such as Tag 1002 / `RPMSIGTAG_PGP`, which cover both the metadata and
		the file archive), the `Rsaheader` signature specifically protects the RPM's structural metadata.

		Here is the step-by-step breakdown of how the RPM software calculates this value under the hood:

		1. Isolate the Target Data: The packaging tool extracts the raw binary data of the RPM's Header section.
		   This block of data includes the header record, the index records (which hold the metadata tags), and the
		   header data store. It strictly excludes the preceding Lead, the Signature Header
		   (which houses the signature tags), and the ensuing Payload (the compressed `cpio` archive).

		2. Compute the Digest: A cryptographic hash is computed over this binary Header data.
		   This is typically a SHA-1 or SHA-256 digest, which the RPM format also stores independently in tags
		   like `RPMSIGTAG_SHA1` (Tag 269) or `RPMSIGTAG_SHA256` (Tag 273).

		3. Generate the RSA Signature: The packager's private OpenPGP RSA key is used to sign the computed digest.

		4. Format as an OpenPGP Packet:The resulting cryptographic signature is encapsulated into an OpenPGP Signature Packet.
		   This MUST generate a OpenPGP Version 4 signature packet

		5. Store the Value
		   The raw bytes of this OpenPGP Signature Packet are written directly into the Signature Header as Tag 268.
		   The data type for this tag is set to `bin` (binary data).
	*/

	// 1. Construct the Version 4 OpenPGP Signature Packet metadata

	config := &packet.Config{
		Time: time.Now,
	}

	// 3. Create the Signature packet explicitly
	sig := CreateSignaturePacket(privKey, config)

	// 3. Sign the populated hash instance
	err := sig.Sign(digest, privKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign header: %w", err)
	}

	// 4. Serialize ONLY the Signature Packet into raw binary bytes
	var buf bytes.Buffer
	err = sig.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signature packet: %w", err)
	}

	return buf.Bytes(), nil
}

func CreateSignaturePacket(privKey *packet.PrivateKey, config *packet.Config) *packet.Signature {

	// 3. Create the Signature packet explicitly
	sig := &packet.Signature{
		Version:      privKey.PublicKey.Version,
		SigType:      packet.SigTypeBinary,
		PubKeyAlgo:   privKey.PubKeyAlgo,
		Hash:         config.Hash(),
		CreationTime: config.Now(),
		IssuerKeyId:  &privKey.PublicKey.KeyId,
	}
	return sig
}

// SignGeneric signs all the input data and returns an ASCII-armored, detached GPG signature
func SignGeneric(dataToSign io.Reader, privKey *packet.PrivateKey) ([]byte, error) {

	sigFile := NewArrayWriter()

	// 2. Wrap output in ASCII armor
	armorWriter, err := armor.Encode(&sigFile, openpgp.SignatureType, nil)
	if err != nil {
		_ = CloseWriter(armorWriter)
		return nil, fmt.Errorf("failed to create armor encoder: %w", err)
	}

	config := &packet.Config{
		Time: time.Now,
	}

	// 3. Create the Signature packet explicitly
	sig := CreateSignaturePacket(privKey, config)

	// 4. Prepare the hash context using the signature packet
	// This ensures PGP-specific headers are hashed properly
	hasher, err := sig.PrepareSign(config)
	if err != nil {
		_ = CloseWriter(armorWriter)
		return nil, fmt.Errorf("failed to prepare signature: %w", err)
	}

	// 5. Stream the target file through the hasher
	if _, err := io.Copy(hasher, dataToSign); err != nil {
		_ = CloseWriter(armorWriter)
		return nil, fmt.Errorf("failed to hash input data: %w", err)
	}

	// 6. Complete the signature (adds the PGP trailer and performs RSA/ECC crypto)
	if err := sig.Sign(hasher, privKey, config); err != nil {
		_ = CloseWriter(armorWriter)
		return nil, fmt.Errorf("crypto signing failed: %w", err)
	}

	// 7. Serialize the signed packet into the armor stream
	if err := sig.Serialize(armorWriter); err != nil {
		_ = CloseWriter(armorWriter)
		return nil, fmt.Errorf("failed to serialize signature: %w", err)
	}

	// Close the armor writer to write the closing ASCII footer
	if err = armorWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close armor writer: %w", err)
	}

	return sigFile.Data, nil
}
