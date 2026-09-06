package common

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type SignatureVerifier interface {
	VerifySignatures(toVerify Set[SignatureVersion]) error
	VerifyV3Signature() error
	VerifyV4Signature() error
	VerifyV6Signature() error
}

type SignatureVerifierImpl struct {
	rpmFile        RpmFile
	mainHeaderData RewindableReader
	payloadReader  io.Reader
	gpgPublicKeys  openpgp.EntityList
}

var _ SignatureVerifier = (*SignatureVerifierImpl)(nil)

// NewSignatureVerifier Creates a new verifier.
// Note that a payloadReader is only required for verifying SIGNATURE_VERSION_V3 signatures.
func NewSignatureVerifier(rpmFile RpmFile, payloadReader io.Reader, gpgPublicKeys openpgp.EntityList) SignatureVerifier {

	mainHeaderData := rpmFile.MainHeader.GetData()
	mainHeaderDataReader := NewArrayReader(mainHeaderData)
	return &SignatureVerifierImpl{
		rpmFile:        rpmFile,
		mainHeaderData: mainHeaderDataReader,
		payloadReader:  payloadReader,
		gpgPublicKeys:  gpgPublicKeys,
	}
}

func (v *SignatureVerifierImpl) VerifySignatures(toVerify Set[SignatureVersion]) error {
	if toVerify.IsEmpty() {
		return errors.New("signature version set cannot be empty, need at least one signature version to verify")
	}

	if toVerify.Contains(SIGNATURE_VERSION_V3) {
		if err := v.VerifyV3Signature(); err != nil {
			return err
		}
	}
	if toVerify.Contains(SIGNATURE_VERSION_V4) {
		if err := v.VerifyV4Signature(); err != nil {
			return err
		}
	}
	if toVerify.Contains(SIGNATURE_VERSION_V6) {
		if err := v.VerifyV6Signature(); err != nil {
			return err
		}
	}
	return nil
}

func (v *SignatureVerifierImpl) VerifyV3Signature() error {

	// a V3 signature covers the main header AND the payload, RSA keys store it in
	// RPMSIGTAG_PGP (tag 1002) and DSA keys in RPMSIGTAG_GPG (tag 1005). The RPM
	// toolchain only ever writes one of the two, depending on the signing key's type
	pgpTag := v.rpmFile.SignatureHeader.FindIndexEntry(SigTagPGP)
	dsaTag := v.rpmFile.SignatureHeader.FindIndexEntry(SigTagGPG)
	if pgpTag == nil && dsaTag == nil {
		return errors.New("Signature header contains neither a RPMSIGTAG_PGP nor a RPMSIGTAG_GPG tag")
	}

	md5Tag := v.rpmFile.SignatureHeader.FindIndexEntry(SigTagMD5)
	if md5Tag == nil {
		return errors.New("Signature header does not contain a RPMSIGTAG_MD5 tag")
	}

	if err := v.mainHeaderData.Rewind(); err != nil {
		return err
	}

	var headerData []byte
	var payload []byte
	var err error

	if headerData, err = io.ReadAll(v.mainHeaderData); err != nil {
		return err
	}

	if payload, err = io.ReadAll(v.payloadReader); err != nil {
		return err
	}
	combined := append(headerData, payload...)

	// verify MD5 tag
	digest := md5.New()
	num, err := digest.Write(combined)
	if len(combined) != num || err != nil {
		if err != nil {
			return err
		}
		return errors.New("failed to calculate RPM file MD5")
	}
	actualMd5 := digest.Sum(make([]byte, 0))
	if !bytes.Equal(actualMd5, md5Tag.payload) {
		return errors.New("MD5 hash mismatch")
	}

	// verify RPMSIGTAG_PGP
	if pgpTag != nil {
		if _, err = VerifySignature(v.gpgPublicKeys, combined, pgpTag.payload); err != nil {
			return errors.New("RPMSIGTAG_PGP verification failure")
		}
	}

	// verify RPMSIGTAG_GPG
	if dsaTag != nil {
		if _, err = VerifySignature(v.gpgPublicKeys, combined, dsaTag.payload); err != nil {
			return errors.New("RPMSIGTAG_GPG verification failure")
		}
	}

	return nil
	/*
		## 3. V3 Signatures (Legacy)

		V3 signatures secure the entire package by hashing both the Main Header and the Payload together.

		* **Relevant Tags (in Signature Header):**
		* `1002` (`RPMSIGTAG_PGP`): RSA binary OpenPGP signature.
		* `1005` (`RPMSIGTAG_GPG`): DSA binary OpenPGP signature.
		* `1004` (`RPMSIGTAG_MD5`): 16-byte binary MD5 hash.

		* **What to Hash:**
		1. Calculate the starting byte offset of the Main Header: `96 (Lead) + padded_sig_size`.
		2. Read from this offset all the way to the **end of the file** (EOF).

		* **Verification:** Extract the binary OpenPGP packet from tag `1002` or `1005`.
			Hash the extracted data range (Main Header + Payload) and pass it to an OpenPGP validation library alongside the signature packet.
	*/
}

func (v *SignatureVerifierImpl) VerifyV4Signature() error {

	// a V4 signature covers the main header only, RSA keys store it in
	// RPMSIGTAG_RSA (tag 268) and DSA keys in RPMSIGTAG_DSA (tag 267)
	rsaHeaderTag := v.rpmFile.SignatureHeader.FindIndexEntry(SigTagRSAHeader)
	dsaHeaderTag := v.rpmFile.SignatureHeader.FindIndexEntry(SigTagDSAHeader)
	if rsaHeaderTag == nil && dsaHeaderTag == nil {
		return errors.New("Signature header contains neither a SigTagRSAHeader nor a SigTagDSAHeader tag")
	}

	if err := v.mainHeaderData.Rewind(); err != nil {
		return err
	}

	var headerData []byte
	var err error

	if headerData, err = io.ReadAll(v.mainHeaderData); err != nil {
		return err
	}

	// verify RPMSIGTAG_RSA
	if rsaHeaderTag != nil {
		if _, err = VerifySignature(v.gpgPublicKeys, headerData, rsaHeaderTag.payload); err != nil {
			return err
		}
	}

	// verify RPMSIGTAG_DSA
	if dsaHeaderTag != nil {
		if _, err = VerifySignature(v.gpgPublicKeys, headerData, dsaHeaderTag.payload); err != nil {
			return err
		}
	}

	// NOTE: RPMSIGTAG_GPG (tag 1005) is deliberately NOT verified here. It holds a V3
	//       signature covering main header AND payload, so it cannot validate against
	//       the main header alone - VerifyV3Signature() is what checks it
	return nil

	/*
			## 4. V4 Signatures (Standard)

			Introduced in RPM 4.x, V4 signatures sign *only* the Main Header to prevent hashing gigabytes of payload during verification.
		    The payload is secured indirectly because its hash is stored securely inside the Main Header.

			* **Relevant Tags (in Signature Header):**
			* `268` (`RPMSIGTAG_RSA`): RSA binary OpenPGP signature.
			* `267` (`RPMSIGTAG_DSA`): DSA binary OpenPGP signature.
			* `269` (`RPMSIGTAG_SHA1`): SHA1 hex string.
			* `272` (`RPMSIGTAG_SHA256`): SHA256 hex string (added in RPM >= 4.14).


			* **What to Hash:**
			1. Jump to the start of the Main Header (`96 + padded_sig_size`).
			2. Read the Main Header's Preamble to extract its `num_indices` and `data_len`.
			3. Calculate the Main Header's exact `raw_size` (`16 + (16 * num_indices) + data_len`).
			4. Read *exactly* these `raw_size` bytes. **Do not include the payload.**


			* **Verification:**
			1. Extract the binary OpenPGP packet from `268` or `267`.
			2. Hash the `raw_size` bytes of the Main Header.
			3. Validate the OpenPGP signature against this hash.
			4. **Payload Trust:** To trust the actual files, parse the Main Header, extract `RPMTAG_PAYLOADDIGEST` (Tag `5092`), and hash the compressed payload to ensure it matches.


	*/
}

func (v *SignatureVerifierImpl) VerifyV6Signature() error {

	/*
		If you are parsing a newer RPM V6 package, Tag 278 is a STRING_ARRAY (type 8).
		The strings inside are Base64-encoded OpenPGP packets.
		You must call base64.StdEncoding.DecodeString(str) on the extracted string first,
		and pass the resulting decoded []byte into the sigPacketBytes parameter above.
	*/

	/*
		V6 Signatures (RPM 6.0+)

		The RPM V6 format modernizes cryptography, drops obsolete algorithms like MD5 and SHA1, and allows for multiple signatures alongside OpenPGP v6 packets.

		* **Relevant Tags (in Signature Header):**
		* `278` (`RPMSIGTAG_OPENPGP`): Unlike V3/V4 which use binary data types, this is a `STRING_ARRAY` (Type 8) containing one or more **Base64-encoded** OpenPGP signatures.
		* `279` (`RPMSIGTAG_SHA3_256`): SHA3-256 hex string of the header.


		* **What to Hash:**
		Identical to V4. You hash *only* the exact unpadded `raw_size` bytes of the Main Header.
		* **Verification:**
		1. Extract the string array from `278`.
		2. Base64-decode the strings into raw OpenPGP binary packets.
		3. Hash the Main Header bytes using the algorithm specified inside the OpenPGP packet (typically SHA-256, SHA-512, or SHA3-256).
		4. Verify the OpenPGP packet against the hash.
		5. **Payload Trust:** Extract `RPMTAG_PAYLOADSHA256` (Tag `5092` - renamed in v6) or `RPMTAG_PAYLOADSHA3_256` from the Main Header to verify the payload.
	*/
	// FIXME: Implement me
	return errors.New("implement me")
}

/*
RPM 4.x will use the new (non-ambiguos) RPM signature tags

Data Point                 Legacy V3 Tag Written?    Modern Tag Used by RPM 4.18+       ID           Data Type
--------------------------------------------------------------------------------------------------------------
Header + Payload Size      No (1000)                 RPMTAG_SIGSIZE / LONGSIGSIZE       257 / 270    INT32 / INT64
MD5 Hash                   No (1004)                 RPMTAG_SIGMD5                      261          BIN (16 bytes)
GPG / PGP Signature        No (1005)                 RPMTAG_RSAHEADER or DSAHEADER      268 or 267   BIN
Payload Uncompressed Size  No (1007)                 RPMTAG_LONGARCHIVESIZE             271          INT64
*/

/*
* Signing of the signature header

STEP 1: Construct the Signature Header Block
┌─────────────────────────────────────────────────────────────┐
│ Index Array:                                                │
│  - Tag 62 (RPMTAG_HEADERSIGNATURES, offset=-128, count=16)  │
│  - Tag 1000 (RPMSIGTAG_PAYLOADSIZE)                         │
│  - Tag 1004 (RPMSIGTAG_SHA256)                              │
│ Data Store:                                                 │
│  - [Payload size integer]                                   │
│  - [SHA-256 string hash of the Main Header]                 │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
STEP 2: Hash the ENTIRE Signature Block
   Calculate SHA-256 / SHA-512 over the raw byte array above.
                               │
                               ▼
STEP 3: Generate the Cryptographic PGP Signature
   Sign that hash using the maintainer's Private Key.
                               │
                               ▼
STEP 4: Append the Signature Tag
   Add a NEW tag (e.g. RPMSIGTAG_RSA) to the end of the
   Signature Header containing the raw signature bytes.
*/

/*
An RPM file is logically divided into four sections: the **Lead**, the **Signature**, the **Header**, and the **Payload**. When you sign an RPM file (e.g., using `rpmsign`), the metadata describing the package in the main Header remains unchanged. Instead, the signing tool writes to and updates tags specifically within the **Signature** section.

Over the years, the mechanisms, cryptographic standards, and specific tags used to store these signatures have evolved significantly. Here are the specific signature headers (tags) that are updated or written during the signing process, broken down by RPM file format version.

---

### RPM v6 (The Modern Standard)

Introduced to eliminate legacy cryptographic algorithms (like MD5 and SHA1) and fix tag numbering clashes, RPM v6 handles signatures natively without backward-compatibility bloat.

When signing an RPM v6 package, the following tags in the Signature section are written or updated:

* **`RPMTAG_OPENPGP` (Tag 278):** The primary v6 signature tag. It contains one or more base64-encoded OpenPGP signatures over the main Header.
* **`RPMTAG_RESERVED` (Tag 999):** Always the last tag in the Signature section, consisting strictly of zero-valued padding. When you sign a package, this reserved space shrinks to accommodate the new `RPMTAG_OPENPGP` data so that the massive Payload section does not need to be rewritten.
* **`RPMTAG_SHA3_256` (Tag 279) / `RPMTAG_SHA256` (Tag 272):** The header digests used to verify the integrity of the data being signed.
* **File-Level Signatures (Optional):** If requested via `--signfiles` or `--signverity`, the tool will generate and inject `RPMTAG_FILESIGNATURES` (Tag 274 for IMA) or `RPMTAG_VERITYSIGNATURES` / `RPMTAG_VERITYSIGNATUREALGO` (Tags 276 and 277 for fsverity).
* **Legacy Fallback Tags:** If a v4 compatibility signature is strictly requested (`rpmsign --rpmv4`), `RPMTAG_RSAHEADER` (Tag 268) or `RPMTAG_DSAHEADER` (Tag 267) may also be written to the v6 signature.

---

### RPM v4 (The Most Common Format)

RPM v4 is the format you will encounter on the vast majority of modern Linux distributions. It introduced a formalized immutable region (denoted by `RPMTAG_HEADERSIGNATURES`) and shifted toward Header-only signatures rather than Header+Payload signatures.

When signing a v4 package, you will see a mix of v4 (Header-only) and occasionally v3 (Header+Payload) tags written:

**Header-Only Signature Tags (v4 native):**

* **`RPMTAG_RSAHEADER` (Tag 268):** Contains the OpenPGP RSA signature applied *only* to the Header.
* **`RPMTAG_DSAHEADER` (Tag 267):** Contains the OpenPGP signature for DSA, EcDSA, or EdDSA applied *only* to the Header.

**Legacy Header+Payload Signature Tags (v3 compatibility):**
*If an RPM v3 signature is requested (`--rpmv3`) or configured by default for older compatibility, these are injected alongside the v4 tags.*

* **`RPMTAG_PGP` (Tag 1002):** RSA signature applied to both the Header and the Payload.
* **`RPMTAG_GPG` (Tag 1005):** DSA/EcDSA signature applied to both the Header and the Payload.

**Integrity and Utility Tags:**

* **`RPMTAG_RESERVEDSPACE` (Tag 1008):** Similar to v6, this is a pre-allocated block of zeros that shrinks when `rpmsign` adds the RSA/DSA tags, saving the I/O cost of shifting the payload.
* **`RPMTAG_SHA256HEADER` (Tag 272) & `RPMTAG_SHA1HEADER` (Tag 269):** Digests of the Header region.
* **`RPMTAG_SIGMD5` (Tag 1004):** A 16-byte MD5 hash covering both the Header and Payload. Note that because of FIPS compliance, v4 packages relying on MD5/SHA1 cannot be signed on strict FIPS-enabled systems.

---

### RPM v3 (Legacy / Historical)

You are highly unlikely to encounter an authentic v3 package today (the last version of RPM that produced these natively was released in 2000), but the structure dictates how the "legacy" tags bundled in v4 packages were originally designed.

In v3, the Signature tags severely clashed with the main Header tags, and all signatures fundamentally covered both the Header and the Payload:

* **`RPMTAG_PGP` (Tag 1002):** The RSA signature bytes for the Header + Payload.
* **`RPMTAG_GPG` (Tag 1005):** The DSA signature bytes for the Header + Payload.
* **`RPMTAG_SIGMD5` (Tag 1004):** The 16-byte MD5 hash of the Header + Payload.
* **`RPMTAG_SIGSIZE` (Tag 1000):** The 32-bit total size of the Header and Payload.

Unlike v4 and v6, v3 did not utilize a formal reserved space tag; padding was simply calculated to an 8-byte boundary, making signing v3 packages a heavy I/O operation because the entire payload often had to be rewritten.
*/

// CreateDestinationFile creates the given file for writing, refusing to clobber
// an already existing file unless overwriteDestinationFile is true.
func CreateDestinationFile(destinationFileName string, overwriteDestinationFile bool) (*os.File, error) {

	_, err := os.Stat(destinationFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat() destination file %s. Error: %s", destinationFileName, err.Error())
		}
		// ok, file does not exist
	} else if !overwriteDestinationFile {
		// no error -> file exists
		return nil, fmt.Errorf("refusing to overwrite destination file %s. Use -f or --overwrite to avoid this error", destinationFileName)
	}
	destinationFile, err := os.Create(destinationFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination file %s. Error: %s", destinationFileName, err.Error())
	}
	return destinationFile, nil
}

func SignRpmAndWriteToFile(rpmFile RpmFile,
	payloadReader ReaderWithOffset,
	destinationFileName string,
	overwriteDestinationFile bool,
	privateKey packet.PrivateKey,
	verboseOutput bool) error {

	destinationFile, err := CreateDestinationFile(destinationFileName, overwriteDestinationFile)
	if err != nil {
		return err
	}
	writer := NewFileWriterWithOffset(destinationFile)
	err = SignRpmAndWrite(rpmFile, writer, payloadReader, privateKey)
	if err != nil {
		_ = os.Remove(destinationFileName)
		_ = CloseWriter(writer)
		return err
	}
	return CloseWriter(writer)
}

func SignRpmAndWrite(rpmFile RpmFile, writer WriterWithOffset, payloadReader ReaderWithOffset, privateKey packet.PrivateKey) error {

	var err error

	err = SignRpm(&rpmFile, privateKey)
	if err != nil {
		return err
	}
	return rpmFile.Write(writer, payloadReader)
}

func SignRpm(rpmFile *RpmFile, privateKey packet.PrivateKey) error {

	var err error

	keyType := GetKeyType(privateKey)

	// Sign digest
	openPgpPacketData, err := SignDigest(rpmFile.MainHeader.Sha256Digest, &privateKey)
	if err != nil {
		return fmt.Errorf("failed to load sign digest: " + err.Error())
	}

	// depending on the private key type (RSA or DSA),
	// we'll have to make sure to delete any signature header index entry
	// that refers to a different private key type
	var newEntryTag SignatureTagValue
	switch keyType {
	case KEY_TYPE_RSA:
		newEntryTag = SigTagRSAHeader
		rpmFile.SignatureHeader.DeleteIndexEntryIfExists(SigTagDSAHeader)
	case KEY_TYPE_DSA:
		newEntryTag = SigTagDSAHeader
		rpmFile.SignatureHeader.DeleteIndexEntryIfExists(SigTagRSAHeader)
	default:
		// FIXME: Implement RPM V6 support
		return fmt.Errorf("sorry, only private keys of type RSA or DSA are supported for signing")
	}

	newEntrySize := uint32(len(openPgpPacketData))
	rpmFile.SignatureHeader.SetOrAddIndexEntry(newEntryTag, FORMAT_TYPE_BINARY, newEntrySize, openPgpPacketData)
	return nil
}
