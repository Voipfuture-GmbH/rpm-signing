package common

// CAREFUL: Endpoints are used by BOTH client and server,
//          the leading slash matters

// PubKeyDownloadEndpoint is a server endpoint
// that returns ASCII-armored GPG public keys
// to verify signatures made by this server
const PubKeyDownloadEndpoint = "/publickey"

// ClientDownloadEndpoint returns the RPM
// client binary
const ClientDownloadEndpoint = "/clientDownload"

// SignRpmHeaderEndpoint receives RPM header data and
// streams the signed RPM header back to the client
const SignRpmHeaderEndpoint = "/signRpmHeader"

// SignDetached receives arbitrary data and
// returns an ASCII-armoreed GPG detached signature
// of that data (suitable for signing RPM
// repository metadata for example)
const SignDetached = "/signDetached"

// InfoEndpoint HTTP endpoint that returns a JSON
// payload describing the server (uptime, version etc.)
const InfoEndpoint = "/info"
