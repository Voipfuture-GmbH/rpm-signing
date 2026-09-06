package main

import (
	"fmt"
	"io"
	"os"
	"rpm-signing/common"
	"strings"
)

func printHelpAndExit(errorMessage ...string) {

	if len(errorMessage) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", errorMessage[0])
		fmt.Println()
	}

	fmt.Printf("Usage: [--version] [-v|--verbose] [--dump|--dump-main-hdr|--dump-sig-hdr] [-i|--info] [--verify] [-d|--debug] " +
		"[-s|--sign] [--sign-generic] [--sign-server <sign server base URL>] [--sign-server-token <token>] [-f|--overwrite] " +
		"[--priv-key <GPG private key file>] [--priv-key-password <password>] [--pub-key <GPG public key file OR directory>] " +
		"[-o|--output-file <RPM FILE>] <RPM file>")
	fmt.Println()
	os.Exit(1)
}

func printVersionAndExit() {

	fmt.Println(common.VersionString())
	os.Exit(0)
}

func printErrorAndExit(errorMessage string) {

	_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", errorMessage)
	os.Exit(1)
}

type SigningMode uint8

var (
	SIGNING_MODE_NOT_SET SigningMode = 0
	SIGNING_MODE_RPM     SigningMode = 1
	SIGNING_MODE_GENERIC SigningMode = 2
)

func main() {

	var err error

	var privateKeyFilename string
	var privateKeyPassphrase []byte
	var gpgPublicFiles []string

	var signServerUrl = ""
	var signServerToken = ""

	var overwriteDestinationFile = false
	var destinationFileName = ""

	// modes
	var verifySignatures = false
	var printInfo = false
	var dumpSignatureHeader = false
	var dumpMainHeader = false
	var verboseOutput = false
	var signingMode SigningMode = SIGNING_MODE_NOT_SET

	seenOpts := common.NewSet[string]()
	failIfNotUnique := func(opt string) {
		if seenOpts.Contains(opt) {
			printHelpAndExit(fmt.Sprintf("CLI option %s most not appear more than once", opt))
		}
		seenOpts.Add(opt)
	}

	var remainingArgs []string
	onlyArgs := os.Args[1:]
	for idx := 0; idx < len(onlyArgs); idx++ {
		arg := onlyArgs[idx]
		if arg == "-help" || arg == "--help" || arg == "-h" {
			printHelpAndExit()
		}
		if arg == "--version" {
			printVersionAndExit()
		}
		if arg == "-o" || arg == "--output-file" {
			if (idx + 1) >= len(onlyArgs) {
				printHelpAndExit(arg + " option requires an argument")
			}
			failIfNotUnique(arg)

			idx++
			if len(destinationFileName) > 0 {
				printHelpAndExit("More than one -o/--output-file option provided")
			}
			destinationFileName = onlyArgs[idx]
		} else if arg == "--priv-key" {
			if (idx + 1) >= len(onlyArgs) {
				printHelpAndExit(arg + " option requires an argument")
			}
			failIfNotUnique(arg)
			idx++
			if len(privateKeyFilename) > 0 {
				printHelpAndExit("More than one --priv-key option provided")
			}
			privateKeyFilename = onlyArgs[idx]
		} else if arg == "--sign-server" {
			if (idx + 1) >= len(onlyArgs) {
				printHelpAndExit(arg + " option requires an argument")
			}
			failIfNotUnique(arg)
			idx++
			signServerUrl = onlyArgs[idx]
		} else if arg == "--sign-server-token" {
			if (idx + 1) >= len(onlyArgs) {
				printHelpAndExit(arg + " option requires an argument")
			}
			failIfNotUnique(arg)
			idx++
			signServerToken = onlyArgs[idx]
		} else if arg == "-f" || arg == "--overwrite" {
			failIfNotUnique(arg)
			overwriteDestinationFile = true
		} else if arg == "-i" || arg == "--info" {
			failIfNotUnique(arg)
			printInfo = true
		} else if arg == "-v" || arg == "--verbose" {
			failIfNotUnique(arg)
			verboseOutput = true
		} else if arg == "--pub-key" {
			if (idx + 1) >= len(onlyArgs) {
				printHelpAndExit(arg + " option requires an argument")
			}
			idx++
			gpgPublicFiles = append(gpgPublicFiles, onlyArgs[idx])
		} else if arg == "--dump" {
			failIfNotUnique(arg)
			dumpMainHeader = true
			dumpSignatureHeader = true
		} else if arg == "--dump-sig-hdr" {
			failIfNotUnique(arg)
			dumpSignatureHeader = true
		} else if arg == "--dump-main-hdr" {
			failIfNotUnique(arg)
			dumpMainHeader = true
		} else if arg == "--priv-key-password" {
			if (idx + 1) >= len(onlyArgs) {
				printHelpAndExit(arg + " option requires an argument")
			}
			idx++
			privateKeyPassphrase = []byte(onlyArgs[idx])
		} else if arg == "--verify" {
			failIfNotUnique(arg)
			verifySignatures = true
		} else if arg == "-s" || arg == "--sign" {
			failIfNotUnique(arg)
			signingMode = SIGNING_MODE_RPM
		} else if arg == "--sign-generic" {
			failIfNotUnique(arg)
			signingMode = SIGNING_MODE_GENERIC
		} else if arg == "-d" || arg == "--debug" {
			failIfNotUnique(arg)
			common.RootLogger().SetCurrentLogLevel(common.LOG_LEVEL_DEBUG)
		} else {
			remainingArgs = append(remainingArgs, arg)
		}
	}

	/*
	 * Commandline arguments sanity checking
	 */
	if len(remainingArgs) == 0 {
		printHelpAndExit("No RPM file name given")
	} else if len(remainingArgs) > 1 {
		printHelpAndExit("Expected exactly one RPM file name but got " + strings.Join(remainingArgs, ", "))
	}

	if signingMode == SIGNING_MODE_GENERIC {
		if len(privateKeyFilename) == 0 {
			printHelpAndExit("--sign-generic option requires --priv-key")
		}
		if len(destinationFileName) == 0 {
			printHelpAndExit("--sign-generic option requires -o/--output-file")
		}
	}

	if seenOpts.Contains("--sign-server-token") && len(signServerUrl) == 0 {
		printHelpAndExit("--sign-server-token requires --sign-server")
	}
	if len(signServerUrl) > 0 {
		if signingMode == SIGNING_MODE_NOT_SET {
			printHelpAndExit("--sign-server can only be used together with -s/--sign or --sign-generic")
		}
		if len(privateKeyFilename) > 0 || privateKeyPassphrase != nil {
			printHelpAndExit("--sign-server is mutually exclusive with --priv-key/--priv-key-password")
		}
	}

	rpmFilePath := remainingArgs[0]

	if verboseOutput {
		common.RootLogger().Infof("Reading input file %s\n", rpmFilePath)
	}

	r, err := common.OpenFileOrUrl(rpmFilePath)
	if err != nil {
		printErrorAndExit(fmt.Sprintf("Failed reading file %s. Error: %v", rpmFilePath, err))
	}

	if signingMode == SIGNING_MODE_GENERIC {

		privateKey, err := common.LoadPrivateKeyFromFile(privateKeyFilename, privateKeyPassphrase)
		if err != nil {
			printHelpAndExit(fmt.Sprintf("Failed to load private key from %s: %v", privateKeyFilename, err))
		}

		detachedSignature, err := common.SignGeneric(r, &privateKey)
		if err != nil {
			printHelpAndExit(fmt.Sprintf("Signing operation failed: %v", err))
		}

		if err := common.WriteFileAtomically(destinationFileName, detachedSignature, 0644, overwriteDestinationFile); err != nil {
			printErrorAndExit(fmt.Sprintf("Failed to write detached GPG signature to %s: %v", destinationFileName, err))
		}
		if verboseOutput {
			common.RootLogger().Infof("Wrote detached GPG signature to %s", destinationFileName)
		}
		os.Exit(0)
	}

	// when signing RPMs remotely, the RPM header is the POST body,
	// so capture it while the RPM parser below reads it anyway
	var headerCapture *headerCapturingReader
	var rpmSource io.Reader = r
	if len(signServerUrl) > 0 && signingMode == SIGNING_MODE_RPM {
		headerCapture = newHeaderCapturingReader(r)
		rpmSource = headerCapture
	}

	rpmFileReader := common.NewIOReaderWithOffset(rpmSource)
	defer common.CloseQuietly(rpmFileReader)

	// NOTE: _NEVER_ perform signature validation here because
	//       validating a V3 signature would mean the whole payload
	//       gets read, moving the reader past the payload
	//       and making subsequent signature verification (if --verify got passed)
	//       fail on V3 signatures because the reader is already EOF
	rpmFile, err := common.ParseRPMFromReader(rpmFileReader, false)
	if err != nil {
		printErrorAndExit("Error during RPM file reading, error: " + err.Error())
		return // unreachable, make compiler happy
	}

	// the parser stopped right at the first payload byte, so the captured
	// bytes are now exactly the RPM header and nothing more
	if headerCapture != nil {
		headerCapture.StopCapturing()
	}

	if printInfo {

		var sigVersion string
		if rpmFile.IsSigned() {
			sigVersion = rpmFile.GetSignatureVersions().String()
		} else {
			sigVersion = "<unsigned>"
		}
		common.RootLogger().Infof("RPM version: %v | RPM file format version: %v | Signature version(s): %v",
			rpmFile.GetRpmVersion(), rpmFile.GetFileFormatVersion().String(), sigVersion)
	}

	if dumpMainHeader || dumpSignatureHeader {

		if dumpSignatureHeader {
			common.RootLogger().Info("--- Signature entries ----")
			common.RootLogger().Info(rpmFile.SignatureHeader.DumpIndexEntries(25, true))
		}
		if dumpMainHeader {
			common.RootLogger().Info("--- Main Header entries ----")
			common.RootLogger().Info(rpmFile.MainHeader.DumpIndexEntries(25, true))
		}
	}

	if verifySignatures && !rpmFile.GetSignatureVersions().IsEmpty() {

		if len(gpgPublicFiles) == 0 {
			printHelpAndExit("Cannot verify signatures without GPG public key, use --pub-key <file>")
		}

		if verboseOutput {
			common.RootLogger().Infof("Verifying against public key %s", gpgPublicFiles)
		}

		// load public keys
		gpgPublicKeys, err := common.LoadPublicKeys(gpgPublicFiles)
		if err != nil {
			printErrorAndExit("Error loading GPG public keys, error: " + err.Error())
		}

		// payload reader is only required for V3 signatures
		// as those sign both the main header AND the payload
		var payloadReader common.SeekableReader
		if rpmFile.GetSignatureVersions().Contains(common.SIGNATURE_VERSION_V3) {
			// NOTE: plain '=' and not ':=' , otherwise payloadReader would only be
			//       assigned inside this block and stay nil for the verifier below
			payloadReader, err = common.OpenFileOrUrl(rpmFilePath)
			if err != nil {
				printErrorAndExit(fmt.Sprintf("Failed to open RPM file %s. Error: %s", rpmFilePath, err.Error()))
				return // unreachable, make compiler happy
			}
			defer common.CloseQuietly(payloadReader)

			err = payloadReader.SeekRelativeToStart(int64(rpmFile.PayloadStartOffset))
			if err != nil {
				printErrorAndExit(fmt.Sprintf("Failed to seek() RPM file %s. Error: %s", rpmFilePath, err.Error()))
			}
		}

		verifier := common.NewSignatureVerifier(rpmFile, payloadReader, gpgPublicKeys)
		versionsPresent := rpmFile.GetSignatureVersions()
		for _, version := range common.AllSignatureVersions() {

			if versionsPresent.Contains(version) {

				switch version {
				case common.SIGNATURE_VERSION_V3:
					err = verifier.VerifyV3Signature()
				case common.SIGNATURE_VERSION_V4:
					err = verifier.VerifyV4Signature()
				case common.SIGNATURE_VERSION_V6:
					err = verifier.VerifyV6Signature()
				}

				if err != nil {
					common.RootLogger().Infof("RPM file signature %v: FAILED (%s)", version, err.Error())
				} else if verboseOutput {
					common.RootLogger().Infof("RPM file signature %v: ok", version)
				}
			} else if verboseOutput {
				common.RootLogger().Infof("RPM file signature %v: <not present>", version)
			}
		}

	} else if rpmFile.GetSignatureVersions().IsEmpty() {
		common.RootLogger().Info("RPM file is unsigned, no signatures to verify")
	}

	if signingMode == SIGNING_MODE_RPM {

		if len(destinationFileName) <= 0 {
			printHelpAndExit(fmt.Sprintf("Cannot sign RPM without -o/--output-file"))
		}

		if headerCapture != nil {
			// sign using remote server
			if verboseOutput {
				common.RootLogger().Infof("Sending %d bytes of RPM header to sign server %s", len(headerCapture.Bytes()), signServerUrl)
			}

			if err = signRpmRemotely(signServerUrl, signServerToken, headerCapture.Bytes(), rpmFileReader,
				destinationFileName, overwriteDestinationFile); err != nil {
				printErrorAndExit(fmt.Sprintf("Failed to sign RPM file %s. Error: %v", destinationFileName, err))
			}
		} else {
			// local signing
			if len(privateKeyFilename) == 0 {
				printHelpAndExit("Cannot --sign without --priv-key")
			}

			privateKey, err := common.LoadPrivateKeyFromFile(privateKeyFilename, privateKeyPassphrase)
			if err != nil {
				printHelpAndExit(fmt.Sprintf("Failed to load private key from %s: %v", privateKeyFilename, err))
			}

			if err = common.SignRpmAndWriteToFile(rpmFile, rpmFileReader, destinationFileName, overwriteDestinationFile, privateKey, verboseOutput); err != nil {
				printErrorAndExit(fmt.Sprintf("Failed to sign RPM file %s. Error: %v", destinationFileName, err))
			}
		}
		common.RootLogger().Infof("Wrote signed file to %s", destinationFileName)
	}
}
