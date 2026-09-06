package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"rpm-signing/common"
	"strings"
)

// maxErrorBodyLength caps how much of an unsuccessful server response is quoted back to the user
const maxErrorBodyLength = 512

// headerCapturingReader copies everything read from src into an internal buffer
// until StopCapturing() is called. It is used to grab the RPM's header bytes
// (everything up to, but not including, the compressed payload) during the
// parsing pass that happens anyway, so the source is only read once.
type headerCapturingReader struct {
	src       io.Reader
	buf       bytes.Buffer
	capturing bool
}

func newHeaderCapturingReader(src io.Reader) *headerCapturingReader {
	return &headerCapturingReader{src: src, capturing: true}
}

func (h *headerCapturingReader) Read(p []byte) (int, error) {
	cnt, err := h.src.Read(p)
	if h.capturing && cnt > 0 {
		h.buf.Write(p[:cnt])
	}
	return cnt, err
}

// Close delegates to the wrapped reader as the RPM parsing code closes
// whatever reader it got handed, and this type sits in the middle of that chain
func (h *headerCapturingReader) Close() error {
	return common.Close(h.src)
}

func (h *headerCapturingReader) StopCapturing() {
	h.capturing = false
}

// Bytes returns everything read while capturing was enabled
func (h *headerCapturingReader) Bytes() []byte {
	return h.buf.Bytes()
}

// createSigningUrl turns the sign server's base URL into the full /sign endpoint URL
// by appending the path (ONLY if no path is already present) and the given
// authToken.
// The authToken query parameter is always sent, with an empty value if no token was given.
func createSigningUrl(serverBaseUrl string, authToken string) (string, error) {

	parsed, err := url.Parse(serverBaseUrl)
	if err != nil {
		return "", fmt.Errorf("not a valid sign server URL '%s': %w", serverBaseUrl, err)
	}
	if len(parsed.Host) == 0 {
		return "", fmt.Errorf("not a valid sign server URL '%s': missing host", serverBaseUrl)
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + common.SignRpmHeader
	parsed.RawQuery = url.Values{"authToken": {authToken}}.Encode()
	return parsed.String(), nil
}

// signRpmRemotely POSTs the RPM's header bytes to the sign server and writes the signed
// header returned by it, immediately followed by the RPM's unchanged compressed payload,
// to destinationFileName.
// The payload reader needs to be positioned at the RPM's first payload byte.
func signRpmRemotely(serverBaseUrl string,
	authToken string,
	rpmHeader []byte,
	payload io.Reader,
	destinationFileName string,
	overwriteDestinationFile bool) error {

	endpointUrl, err := createSigningUrl(serverBaseUrl, authToken)
	if err != nil {
		return err
	}

	// a *bytes.Reader gives the request an exact Content-Length, avoiding chunked encoding
	request, err := http.NewRequest(http.MethodPost, endpointUrl, bytes.NewReader(rpmHeader))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("POST to sign server failed: %w", err)
	}
	defer common.CloseQuietly(response.Body)

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyLength))
		return fmt.Errorf("sign server responded with %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	destinationFile, err := common.CreateDestinationFile(destinationFileName, overwriteDestinationFile)
	if err != nil {
		return err
	}

	// io.MultiReader implements io.WriterTo, so this streams the response body and the
	// payload back-to-back into the destination file without buffering either of them
	if _, err = io.Copy(destinationFile, io.MultiReader(response.Body, payload)); err != nil {
		_ = destinationFile.Close()
		_ = os.Remove(destinationFileName)
		return fmt.Errorf("failed to write %s: %w", destinationFileName, err)
	}
	return destinationFile.Close()
}
