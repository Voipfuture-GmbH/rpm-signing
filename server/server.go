package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"rpm-signing/common"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const REQUEST_PARAM_AUTH_TOKEN = "authToken"

type AppConfig struct {
	Verbose               bool
	DebugMode             bool
	GpgPublicKeyPath      string
	GpgPrivateKeyPath     string
	GpgPrivateKeyPassword []byte
	ApiSigningToken       string
	ListenAddress         string
	RpmSignClientBinary   string
	AccessLogPath         string
}

// defaultListenAddress is used when the configuration file has no 'listen_address' key.
const defaultListenAddress = ":8080"

func (app *AppConfig) LoadGpgPrivateKey() (packet.PrivateKey, error) {

	reader, err := os.Open(app.GpgPublicKeyPath)
	defer common.CloseQuietly(reader)
	if err != nil {
		return packet.PrivateKey{}, err
	}
	return common.LoadPrivateKeyFromFile(app.GpgPrivateKeyPath, app.GpgPrivateKeyPassword)
}

func (app *AppConfig) LoadGpgPublicKeyAsBytes() ([]byte, error) {
	return os.ReadFile(app.GpgPublicKeyPath)
}

func (app *AppConfig) LoadGpgPublicKey() (openpgp.EntityList, error) {

	reader, err := os.Open(app.GpgPublicKeyPath)
	defer common.CloseQuietly(reader)
	if err != nil {
		return nil, err
	}
	return common.LoadPublicKey(reader)
}

func stringToBoolean(s string) (bool, error) {
	if len(s) > 0 {
		var result bool
		var err error
		switch strings.TrimSpace(s) {
		case "1", "on", "true":
			result = true
		case "0", "off", "false":
			result = false
		default:
			err = fmt.Errorf("not a valid boolean value: '%s' (only 1,0,true,false,on,off are accepted)", s)
		}
		return result, err
	}
	return false, errors.New("stringToBoolean() called with blank value")
}

func assertFileExists(filename string) (string, error) {
	exists, err := common.FileExists(filename)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("file '%s' does not exist", filename)
	}
	return filename, nil
}

func loadAppConfigFromReader(reader io.ReadCloser) (AppConfig, error) {

	defer common.CloseQuietly(reader)
	lines, err := common.ReadLines(reader)
	if err != nil {
		return AppConfig{}, err
	}

	seenOpts := common.NewSet[string]()
	failIfNotUnique := func(opt string) {
		if seenOpts.Contains(opt) {
			_, _ = fmt.Fprintf(os.Stderr, "Config file option %s most not appear more than once", opt)
			os.Exit(1)
		}
		seenOpts.Add(opt)
	}

	var result AppConfig
	for lineNo, line := range lines {

		runes := []rune(line)
		firstNonWhitespaceIdx := -1
		for idx, r := range runes {
			if !unicode.IsSpace(r) {
				firstNonWhitespaceIdx = idx
				break
			}
		}
		if firstNonWhitespaceIdx == -1 || runes[firstNonWhitespaceIdx] == '#' {
			// skip blank and comments line
			continue
		}
		equalsIdx := strings.Index(line, "=")
		if equalsIdx == -1 {
			return AppConfig{}, fmt.Errorf("config file has error on line %d: Malformed, needs to be <key>=<value>", lineNo+1)
		}
		key := strings.TrimSpace(line[0:equalsIdx])
		value := strings.TrimSpace(line[equalsIdx+1:])

		if len(key) == 0 {
			return AppConfig{}, fmt.Errorf("config file has error on line %d: Malformed, needs to be <key>=<value>", lineNo+1)
		}

		failIfNotUnique(key)
		switch key {
		case "verbose":
			result.Verbose, err = stringToBoolean(value)
			if err != nil {
				return AppConfig{}, fmt.Errorf("config file has error on line %d: %w", lineNo+1, err)
			}
		case "debug":
			result.DebugMode, err = stringToBoolean(value)
			if err != nil {
				return AppConfig{}, fmt.Errorf("config file has error on line %d: %w", lineNo+1, err)
			}
		case "gpg_public_key":
			result.GpgPublicKeyPath, err = assertFileExists(value)
			if err != nil {
				return AppConfig{}, fmt.Errorf("config file has error on line %d: %w", lineNo+1, err)
			}
		case "gpg_private_key":
			result.GpgPrivateKeyPath, err = assertFileExists(value)
			if err != nil {
				return AppConfig{}, fmt.Errorf("config file has error on line %d: %w", lineNo+1, err)
			}
		case "access_log":
			result.AccessLogPath = value
		case "gpg_private_key_password":
			result.GpgPrivateKeyPassword = []byte(value)
		case "api_signing_token":
			result.ApiSigningToken = value
		case "listen_address":
			result.ListenAddress = value
		case "rpm_sign_client_binary":
			// optional, but a path that is given must point at an existing file
			if len(value) > 0 {
				result.RpmSignClientBinary, err = assertFileExists(value)
				if err != nil {
					return AppConfig{}, fmt.Errorf("config file has error on line %d: %w", lineNo+1, err)
				}
			}
		default:
			return AppConfig{}, fmt.Errorf("config file has error on line %d: Unrecognized key '%s'", lineNo+1, key)
		}
	}
	if len(result.ApiSigningToken) == 0 {
		return AppConfig{}, fmt.Errorf("configuration file needs to contain a non-blank 'api_signing_token'")
	}
	if len(result.ListenAddress) == 0 {
		result.ListenAddress = defaultListenAddress
	}

	_, err = result.LoadGpgPublicKey()
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to load GPG public key %s: %w", result.GpgPublicKeyPath, err)
	}

	_, err = result.LoadGpgPrivateKey()
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to load GPG private key %s: %w", result.GpgPrivateKeyPath, err)
	}

	return result, nil
}

func loadAppConfigFromFile(file string) (AppConfig, error) {
	reader, err := os.Open(file)
	if err != nil {
		return AppConfig{}, err
	}
	return loadAppConfigFromReader(reader)
}

func loadAppConfig(args []string) (AppConfig, error) {

	var err error

	configFilePath := os.Getenv("RPM_SIGN_CONFIG")

	seenOpts := common.NewSet[string]()
	failIfNotUnique := func(opt string) error {
		if seenOpts.Contains(opt) {
			return fmt.Errorf("CLI option %s is unique but was used more than once", opt)
		}
		seenOpts.Add(opt)
		return nil
	}

	for idx, arg := range args {
		if arg == "-d" || arg == "--debug" {
			if err = failIfNotUnique(arg); err != nil {
				return AppConfig{}, err
			}
		} else if arg == "-v" || arg == "--verbose" {
			if err = failIfNotUnique(arg); err != nil {
				return AppConfig{}, err
			}
		} else if arg == "-c" || arg == "--config" {
			if err = failIfNotUnique(arg); err != nil {
				return AppConfig{}, err
			}
			if (idx + 1) >= len(args) {
				return AppConfig{}, fmt.Errorf("invalid command line, %s option requires an argument", arg)
			}
			if len(configFilePath) == 0 {
				configFilePath = args[idx+1]
			} else {
				common.RootLogger().Infof("Configuration file path from '-c' (%s) overridden by RPM_SIGN_CONFIG env variable (%s)", args[idx+1], configFilePath)
			}
			idx++
		}
	}
	if len(configFilePath) == 0 {
		return AppConfig{}, fmt.Errorf("no configuration file specified, use either -c/--config or set RPM_SIGN_CONFIG")
	}
	result, err := loadAppConfigFromFile(configFilePath)
	if err == nil {
		// the flags override the config file, but only when actually given on the
		// command line, otherwise they would always reset the file's values
		if seenOpts.Contains("-v") || seenOpts.Contains("--verbose") {
			result.Verbose = true
		}
		if seenOpts.Contains("-d") || seenOpts.Contains("--debug") {
			result.DebugMode = true
		}
	}
	return result, err
}

// signRpmData expected rpmData to be everything except the RPM file's payload
// and will return that data signed with the application's GPG private key
func signRpmData(reader common.ReaderWithOffset, writer common.WriterWithOffset, config AppConfig) error {

	rpmFile, err := common.ParseRPMFromReader(reader, false)
	if err != nil {
		return err
	}

	privateKey, err := config.LoadGpgPrivateKey()
	if err != nil {
		return err
	}
	err = common.SignRpmAndWrite(rpmFile, writer, reader, privateKey)
	if err != nil {
		return err
	}
	return nil
}

func initBinaryUncacheableHttpResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func sendHttpError(code int, msg string, w http.ResponseWriter) {
	http.Error(w, msg, code)
}

// handlePublicKey serves GET /publickey and returns the application's GPG public key
func handlePublicKey(w http.ResponseWriter, appConfig AppConfig) {

	publicKey, err := appConfig.LoadGpgPublicKeyAsBytes()
	if err != nil {
		common.RootLogger().Errorf("Failed to load GPG public key %s: %v", appConfig.GpgPublicKeyPath, err)
		sendHttpError(http.StatusInternalServerError, "failed to load GPG public key", w)
		return
	}
	initBinaryUncacheableHttpResponse(w)
	_, err = w.Write(publicKey)
	if err != nil {
		common.RootLogger().Errorf("Failed to write request body to  %s: %v", w, err)
		sendHttpError(http.StatusBadRequest, "failed to read request body", w)
	}
}

func doSigDetached(input io.Reader, appConfig AppConfig) ([]byte, error) {
	privateKey, err := appConfig.LoadGpgPrivateKey()
	if err != nil {
		return nil, err
	}

	signature, err := common.SignGeneric(input, &privateKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// handleSignRpmHeader receives arbitrary data and
// returns an ASCII-armoreed GPG detached signature
// of that data (suitable for signing RPM
// repository metadata for example)
func handleSignDetached(w http.ResponseWriter, r *http.Request, appConfig AppConfig) {

	// constant-time comparison because the token is a shared secret
	token := r.URL.Query().Get(REQUEST_PARAM_AUTH_TOKEN)
	if subtle.ConstantTimeCompare([]byte(token), []byte(appConfig.ApiSigningToken)) != 1 {
		common.RootLogger().Errorf("Rejected /sign request from %s: missing or wrong authToken", r.RemoteAddr)
		sendHttpError(http.StatusForbidden, "missing or invalid authToken", w)
		return
	}

	signature, err := doSigDetached(r.Body, appConfig)
	if err != nil {
		common.RootLogger().Errorf("Failed to sign incoming generic data from %s: %v", r.RemoteAddr, err)
		sendHttpError(http.StatusBadRequest, "failed to sign data", w)
		return
	}

	initBinaryUncacheableHttpResponse(w)
	if _, err = w.Write(signature); err != nil {
		// too late for an error status, the response body is already being written
		common.RootLogger().Errorf("Failed to write signed RPM data to %s: %v", r.RemoteAddr, err)
	}
}

// handleSign serves POST /sign and returns the request body signed with the application's GPG private key
func handleSignRpmHeader(w http.ResponseWriter, r *http.Request, appConfig AppConfig) {

	// constant-time comparison because the token is a shared secret
	token := r.URL.Query().Get("authToken")
	if subtle.ConstantTimeCompare([]byte(token), []byte(appConfig.ApiSigningToken)) != 1 {
		common.RootLogger().Errorf("Rejected /sign request from %s: missing or wrong authToken", r.RemoteAddr)
		sendHttpError(http.StatusForbidden, "missing or invalid authToken", w)
		return
	}

	reader := common.NewIOReaderWithOffset(r.Body)

	// the signed data is assembled in memory instead of being streamed straight into the
	// response because net/http closes the request body as soon as the first response bytes
	// are flushed, and RpmFile.Write() still reads from that body after writing the headers.
	// Buffering also keeps a signing failure reportable, as no status code has been sent yet.
	var signedData bytes.Buffer
	err := signRpmData(reader, common.NewOffsetTrackingWriter(&signedData), appConfig)
	if err != nil {
		// the error is only logged, never returned, as it may disclose server-side file paths
		common.RootLogger().Errorf("Failed to sign incoming RPM data from %s: %v", r.RemoteAddr, err)
		sendHttpError(http.StatusBadRequest, "failed to sign RPM data", w)
		return
	}

	initBinaryUncacheableHttpResponse(w)
	if _, err = w.Write(signedData.Bytes()); err != nil {
		// too late for an error status, the response body is already being written
		common.RootLogger().Errorf("Failed to write signed RPM data to %s: %v", r.RemoteAddr, err)
		return
	}
}

var serverStartTime = time.Now()

// handleVersionRequest serves GET /version and returns
// a JSON response with the application version etc.
func handleVersionRequest(w http.ResponseWriter, r *http.Request, appConfig AppConfig) {

	serverStart := serverStartTime.Format(time.RFC3339)
	json := `{ application: "rpm-signing", serverStart: "` + serverStart + `", version:"` + common.AppVersion + `", gitRef: "` + common.GitRef + `"}`

	initBinaryUncacheableHttpResponse(w)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(json)); err != nil {
		// too late for an error status, the response body is already being written
		common.RootLogger().Errorf("Failed to stream version JSON to %s: %v", r.RemoteAddr, err)
	}
}

// handleClientDownload serves GET /clientDownload and streams the client binary
// configured via 'rpm_sign_client_binary'. Returns 400 when that option is not set.
func handleClientDownload(w http.ResponseWriter, r *http.Request, appConfig AppConfig) {

	if len(appConfig.RpmSignClientBinary) == 0 {
		common.RootLogger().Errorf("Rejected /clientDownload request from %s: no 'rpm_sign_client_binary' configured", r.RemoteAddr)
		sendHttpError(http.StatusBadRequest, "no client binary configured", w)
		return
	}

	file, err := os.Open(appConfig.RpmSignClientBinary)
	if err != nil {
		// the error is only logged, never returned, as it may disclose server-side file paths
		common.RootLogger().Errorf("Failed to open client binary %s: %v", appConfig.RpmSignClientBinary, err)
		sendHttpError(http.StatusInternalServerError, "failed to open client binary", w)
		return
	}
	defer common.CloseQuietly(file)

	initBinaryUncacheableHttpResponse(w)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(appConfig.RpmSignClientBinary)))
	if _, err = io.Copy(w, file); err != nil {
		// too late for an error status, the response body is already being written
		common.RootLogger().Errorf("Failed to stream client binary to %s: %v", r.RemoteAddr, err)
	}
}

var accessLog *os.File = nil
var attemptedAccessLogOpen bool = false

func writeAccessLog(logLine string, appConfig AppConfig) {

	var err error
	if accessLog == nil {

		if len(appConfig.AccessLogPath) == 0 || attemptedAccessLogOpen {
			common.RootLogger().Infof(logLine)
			return
		}
		accessLog, err = os.Create(appConfig.AccessLogPath)
		attemptedAccessLogOpen = true
		if err != nil {
			common.RootLogger().Errorf("Failed to open access log file %s: %v", appConfig.AccessLogPath, err)
			return
		}
	}

	_, err = accessLog.Write([]byte(logLine))
	if err != nil {
		common.RootLogger().Errorf("Failed to write to access log (no more access log will be written!) %s: %v", appConfig.AccessLogPath, err)
		_ = accessLog.Close()
		accessLog = nil
	}
}

// responseWriterWrapper captures status code and bytes written
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// AccessLogMiddleware formats logs using the Apache Combined Log Format
func AccessLogMiddleware(next http.Handler, appConfig AppConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		// Combined Log Format: client_ip - - [timestamp] "method path proto" status bytes "referer" "user_agent"
		timestamp := start.Format("02/Jan/2006:15:04:05 -0700")
		referer := r.Referer()
		if referer == "" {
			referer = "-"
		}
		userAgent := r.UserAgent()
		if userAgent == "" {
			userAgent = "-"
		}

		var uri string
		if appConfig.DebugMode {
			uri = r.URL.RequestURI()
		} else {
			uri = r.URL.Scheme + "://" + r.Host + r.URL.Path
		}

		logLine := fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
			r.RemoteAddr,
			timestamp,
			r.Method,
			uri,
			r.Proto,
			wrapper.statusCode,
			wrapper.bytesWritten,
			referer,
			userAgent,
		)
		writeAccessLog(logLine, appConfig)
	})
}

// startHttpServer serves the signing API until the process receives SIGINT or SIGTERM
func startHttpServer(appConfig AppConfig) error {

	mux := http.NewServeMux()

	// method-aware patterns: the mux itself answers 405 for a wrong method
	// on a known path and 404 for any other URL
	mux.HandleFunc("GET "+common.PubKeyDownloadEndpoint, func(w http.ResponseWriter, r *http.Request) {
		handlePublicKey(w, appConfig)
	})
	mux.HandleFunc("POST "+common.SignRpmHeaderEndpoint, func(w http.ResponseWriter, r *http.Request) {
		handleSignRpmHeader(w, r, appConfig)
	})
	mux.HandleFunc("POST "+common.SignDetached, func(w http.ResponseWriter, r *http.Request) {
		handleSignDetached(w, r, appConfig)
	})
	mux.HandleFunc("GET "+common.ClientDownloadEndpoint, func(w http.ResponseWriter, r *http.Request) {
		handleClientDownload(w, r, appConfig)
	})
	mux.HandleFunc("GET "+common.InfoEndpoint, func(w http.ResponseWriter, r *http.Request) {
		handleVersionRequest(w, r, appConfig)
	})

	server := &http.Server{Addr: appConfig.ListenAddress, Handler: AccessLogMiddleware(mux, appConfig)}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenErr := make(chan error, 1)
	common.RootLogger().Infof("Listening on %s", appConfig.ListenAddress)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
		}
	}()

	select {
	case err := <-listenErr:
		return err
	case <-ctx.Done():
		common.RootLogger().Info("Signal received, shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func main() {

	// handled before loadAppConfig() because printing the version
	// must not require a configuration file
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Println(common.VersionString())
			os.Exit(0)
		}
	}

	common.RootLogger().SetCurrentLogLevel(common.LOG_LEVEL_INFO)
	common.RootLogger().Infof("Server started at %s, version: %s\n", time.Now(), common.VersionString())

	var err error
	appConfig, err := loadAppConfig(os.Args[1:])
	if err != nil {
		common.RootLogger().Errorf("Failed to load application configuration: %v", err)
		os.Exit(1)
	}
	if appConfig.DebugMode {
		common.RootLogger().SetCurrentLogLevel(common.LOG_LEVEL_TRACE)
	} else if appConfig.Verbose {
		common.RootLogger().SetCurrentLogLevel(common.LOG_LEVEL_DEBUG)
	}

	if err := startHttpServer(appConfig); err != nil {
		common.RootLogger().Errorf("Failed to start HTTP server: %v", err)
		os.Exit(1)
	}
}
