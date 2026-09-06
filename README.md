# What's this

This is a very minimal (RPM V4 signatures only) distributed RPM signing system ; basically a HTTP endpoint that receives an HTTP POST with only the header of the RPM file that should be signing (RPM V4 and later signatures 
do not need the payload anymore) and sends back the updated file header. The custom client merges that server response with the compressed payload and voilà ... a signed RPM.

The whole project consists of two binary files (aptly named 'client' and 'server') without any external dependencies. You don't need the server part, the client binary can do signing on its own as well (in fact, both client and server share the same code for RPM parsing and signing).

# CAREFUL !

This whole project is intended to be run inside a local network (not accessible) from the internet where either all clients can be trusted to behave OR sufficient measures (TLS reverse proxy, firewall rules etc.) have been 
put in place to prevent the worst from happening.

This is currently very much the MVP and neither performance nor protection from abuse/attackers was on my feature list. I verified that the RPM parsing is sane by feeding ~5000 Rocky Linux RPMs to it as well as checking that RPMs signed by this tool pass validation by regular RPM.

## Server-side

### HTTP endpoint description

* GET /publickey

  Returns an armored GPG keyring containing the GPG public keys of any signing keys the server is using/used to sign RPMs
  
* GET /clientDownload

  Returns the server's version of the client binary. Will return HTTP Bad Request if the server did not get configured to return the client.
  
* POST /signRpmHeader?authToken=<....token....>

  Expects the POST body to be the whole RPM file header up to (but not including) the payload. If the given authentication token is missing or wrong, the server will respond with a HTTP Forbidden.
  Technically one COULD also post the whole RPM file (including the payload) but this is very wasteful and since the server will hold everything in memory, might lead to a DoS when trying to push very large RPMs.

### Configuration file

The server executable requires either a "-c <config file>" option or an `RPM_SIGN_CONFIG` environment variable pointing to the configuration file to use.
The configuration file uses properties file syntax (`key=value` , '#' for comments) but does _NOT_ support comments at the end of a 'key=value' line (you have been warned)

A sample configuration can be found in the documentation/rpm-signing.properties file

## Client-side

Since both server and client share the same code, the client can sign RPMs on its one just fine.
| Option | Valid values | Example | Description |
|---|---|---|---|
| `-h`, `-help`, `--help` | *(flag, no value)* | `--help` | Prints the usage message and exits with status 1. Checked before all other options. |
| `--version` | *(flag, no value)* | `--version` | Prints the version string (`common.VersionString()`) and exits with status 0. |
| `-v`, `--verbose` | *(flag, no value)* | `--verbose` | Enables verbose output: logs the file being read, the public keys used, and per-signature-version "ok" / "not present" results. |
| `-d`, `--debug` | *(flag, no value)* | `--debug` | Sets the root logger's log level to `DEBUG`. |
| `-i`, `--info` | *(flag, no value)* | `--info` | Prints RPM version, RPM file format version and the signature version(s) present (or `<unsigned>`). |
| `--dump` | *(flag, no value)* | `--dump` | Dumps both the signature header and the main header index entries. Equivalent to `--dump-sig-hdr --dump-main-hdr`. |
| `--dump-sig-hdr` | *(flag, no value)* | `--dump-sig-hdr` | Dumps only the signature header index entries. |
| `--dump-main-hdr` | *(flag, no value)* | `--dump-main-hdr` | Dumps only the main header index entries. |
| `--verify` | *(flag, no value)* | `--verify` | Verifies all signatures (V3, V4, V6) present in the RPM against the given public key(s). Requires at least one `--pub-key`. Skipped silently if the RPM is unsigned. |
| `--sign-server` | Base URL of a signing server | `--sign-server http://signer:8080` | Signs the RPM remotely: the header (everything up to the payload) is POSTed to `<base url>/signRpmHeader` and the response is merged with the local payload into the output file. Only valid together with `-s`/`--sign`, and mutually exclusive with `--priv-key` and `--priv-key-password`. |
| `-s`, `--sign-rpm` | *(flag, no value)* | `--sign` | Signs the RPM and writes the result to the output file. Requires `--sign-server` / `--priv-key` and `-o`/`--output-file`. |
| `--sign-generic` | *(flag, no value)* | `--sign-generic` | Creates an ASCII-armored, detached GPG signature over the whole input file and writes it to the output file. Requires `--priv-key` / `--sign-server` and `-o`/`--output-file`. |
| `--sign-server-token` | Authentication token | `--sign-server-token "s3cret"` | Value sent as the `authToken` query parameter to the signing server. Optional; when omitted an empty `authToken` is sent. Using it without `--sign-server` is an error. |
| `-f`, `--overwrite` | *(flag, no value)* | `--overwrite` | Allows the output file given via `-o`/`--output-file` to be overwritten if it already exists. |
| `-o`, `--output-file` | Path to the RPM file to write | `-o /tmp/signed.rpm` | Destination file for the signed RPM. Mandatory when `--sign` is used. |
| `--priv-key` | Path to a GPG private key file | `--priv-key ~/.gnupg/signing.asc` | GPG private key used for signing. Mandatory when `--sign` is used. |
| `--priv-key-password` | Passphrase string for the private key | `--priv-key-password "s3cret"` | Passphrase used to decrypt the private key. Optional (omit for an unprotected key). |
| `--pub-key` | Path to a GPG public key file **or** a directory | `--pub-key /etc/pki/rpm-gpg/` | GPG public key(s) used by `--verify`. May be repeated to accumulate several keys. If a directory is given, all files in it are loaded. |
| *(positional argument)* | Path to a local RPM file, or an `http://` / `https://` URL | `mypackage-1.0-1.x86_64.rpm` | The RPM file to operate on. Exactly one must be given; zero or more than one is an error. |
