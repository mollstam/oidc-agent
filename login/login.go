package login

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/toqueteos/webbrowser"
	"golang.org/x/oauth2"
)

const redirectURIAuthCodeInTitleBar = "urn:ietf:wg:oauth:2.0:oob"

const tlsCertificate = "-----BEGIN CERTIFICATE-----
MIIDETCCAfkCFEdJ+xNmn+10I/Ruh7LTAvyCepX+MA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAlNFMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjIwNTMwMTQxNDIxWhcNMjMwNTMwMTQx
NDIxWjBFMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA5BDdqO5icZZuIG66bcvfS2PxEODz17HnC0zrIW7oUt4XsD6e
Qe3m2t5uOJ8waJGeudl5QdfRmYQ32BjO+jot8gUFWFZeG7xH3B6ZqiTA3Qb2oMqW
rIj9i7c2k3Iypc0pb7bznwXqTDFoM57LPNSaEL47fstf239rf6Ne8drfWP0H/yjk
6yLR2ocqju3rKTOLx8DLPVe4mTaX7F65pI8RvRmZshOgeFcB86I+glB9a4t1dmVj
dr7ZijnD3xr614R40JtNb/eqWzX2hYP6hNSSdx+XYqbFaDBgyc88LaxNUXEBiI2Q
fSOjN14CGoQ/j8Fmgc7kpnL9lremFh62YNFDaQIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQBdnBVqja4Q9M/kikTNHcxhD4Vvy74qhjd3s750ZiDhPMk2jvkR0nSSOOB+
wuShw0+JIYV3qQ+TfjRQTNZVfZ3sYn0KUtoNQCExsy3KXXWLC694zOOUSGjuKA0A
h9KVG/OXOc7z5jm2nL0RjdOztcZXyIjYP63ZzphHNhWX83yvFY7z2vlR5Kz2MTrQ
GE2i8LSfjwZayGVI74clKqn2WPJfzvIKQ7xyFFRPo622ioD3ngy0wrM/2JJZBgFq
+ikgEAMkPDk6+sWKVdTfkZRBQnyjHjevmfHq2jWhtrgZj3ikHohI+10JBYvYWW6U
a2sbzF3Mzgx4EoTAku/nk8yrMwkt
-----END CERTIFICATE-----"

const tlsPrivateKey = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDkEN2o7mJxlm4g
brpty99LY/EQ4PPXsecLTOshbuhS3hewPp5B7eba3m44nzBokZ652XlB19GZhDfY
GM76Oi3yBQVYVl4bvEfcHpmqJMDdBvagypasiP2LtzaTcjKlzSlvtvOfBepMMWgz
nss81JoQvjt+y1/bf2t/o17x2t9Y/Qf/KOTrItHahyqO7espM4vHwMs9V7iZNpfs
XrmkjxG9GZmyE6B4VwHzoj6CUH1ri3V2ZWN2vtmKOcPfGvrXhHjQm01v96pbNfaF
g/qE1JJ3H5dipsVoMGDJzzwtrE1RcQGIjZB9I6M3XgIahD+PwWaBzuSmcv2Wt6YW
HrZg0UNpAgMBAAECggEBAI7VtU14xzTmhuBPGPls5tNbq33rtSwQomgka1qMEHrd
164s+YbHDX9kMVnK8VF8ahFxj4zaMs5XzXXMy8xRpbbeyCM0LEpomATXMVwrGpMT
KmE3oDg8r7bSLx8XNXs7y8jIpzmgRcYkZ2N0/0qAyGDWE4LssoNRAS12Tx9f+ePL
no1lOo8oVUVIP4lS+OdNhqqn80p2MqGN1+7z+oU1o14iamW559ZAtNUPa25GCSlb
fLiihhVkD4lJHDf759LNivJEMRWkRQ/UI5zgCQOZ05cTQ2miFsPTJrk2Em724XlP
HH07GXOHjVt3JI32d8MIMnpKXbIwGyGKiZPNzM1am+UCgYEA8ihX0gYFEvAxh4Vr
+vKZBQC0MdZjjDy8r0MCGnr7uQ+vGWW2mEAcMHFbsZQC56UlSVfZ0KZ1uN/Z89au
EiON3EK5d6zKED4tbaeyvft5u5Q+JsbLx8ImbHvvgLkxmKeqTMFKx4ZEgTO444II
qrNxb2SHtfCTJXATWzru1H8pe08CgYEA8RpPKy3/M0HxdvGd0QnsxlT+moWzDs4s
v0YTG9vUZTJUPN/0igfQeEVBw30CoBniYgG45MmsaNatpEeEyrkoERUU/TmuFLu7
50U+DhqauwnU+z8rbXrERtfYXL0jmjxP7DR307HD1xg3yj65oSNj3uyMhRiyD/Zb
RkHiUh3Ix8cCgYEAmecyCXVx/BtUH0GY4yEUR62u2I3dLt/bO7hmudW37mIdcxLF
/fWg9NjW4gGj5v16uSZwdL+WyizbJLIoZ7bZDkgKABl9Qt2BmdOfMkeFksYgyhxG
n2qxaPlLuo/5CYBmJ+ohULXxC/yHYXDfeT4atiU6a1O+8WhNpQnLiJpZDtkCgYEA
volcJ3OiSo/Ck40+ewSs6dAhpVwjtX+aPU7TqyB/KboseC9EwhCK34FcB3GzsXLD
RVC3HZeDeRavAzTB7LOGxnkyrSv4NspmJM7Dy8GaplWOyz+QwmRS2OmbQy72A93G
C5UrXVEOw92PuXT4ni+prXKjWku57IN0foFyqhJ/qeECgYBrTW2fTG7DgsoqlkGJ
rFMMRns/EhkN3JzWrN5H43to4wF0IuC8r9LNeKrS8Kre2NT7nu4Rul+mMuY89DG1
H+eyyxCiFnR5h8znXz3Zh0riNfq1kf1gnzLkpH6DktwFx7qNoH51r6JhqvPh/zU/
h1QHGuGpPf0o5JDtP6Ix1uRHCQ==
-----END PRIVATE KEY-----"

var promptConsent oauth2.AuthCodeOption = oauth2.SetAuthURLParam("prompt", "consent")

// LoginAgent implements the OAuth2 login dance, generating an Oauth2 access_token
// for the user. If AllowBrowser is set to true, the agent will attempt to
// obtain an authorization_code automatically by executing OpenBrowser and
// reading the redirect performed after a successful login. Otherwise, it will
// attempt to use In and Out to direct the user to the login portal and receive
// the authorization_code in response.
type LoginAgent struct {
	// Whether to execute OpenBrowser when authenticating the user.
	SkipBrowser bool

	// Read input from here; if nil, uses os.Stdin.
	In io.Reader

	// Write output to here; if nil, uses os.Stdout.
	Out io.Writer

	// Open the browser for the given url.  If nil, uses webbrowser.Open.
	OpenBrowser func(url string) error

	// OIDC Client id/secret
	ClientID     string
	ClientSecret string
	Audience     string

	Endpoint        oauth2.Endpoint
	ExtraScope      []string
	ExtraAuthParams map[string]string
}

// populate missing fields as described in the struct definition comments
func (a *LoginAgent) init() {
	if a.In == nil {
		a.In = os.Stdin
	}
	if a.Out == nil {
		a.Out = os.Stdout
	}
	if a.OpenBrowser == nil {
		a.OpenBrowser = webbrowser.Open
	}
}

func (a *LoginAgent) PerformServerTest(callbackPort int) (error) {
	a.init()

	fmt.Fprintln(a.Out, "DEBUG: Running PerformServerTest")

	if ln, port, err := getListener(a, callbackPort); err == nil {
		defer ln.Close()
		fmt.Fprintln(a.Out, "Running server test on port %d -- %v", port, ln.Addr())
		greetAnyRequest(ln)
	} else {
		return err
	}

	return nil
}

// PerformLogin performs the auth dance necessary to obtain an
// authorization_code from the user and exchange it for an Oauth2 access_token.
func (a *LoginAgent) PerformLogin(callbackPort int) (oauth2.TokenSource, error) {
	a.init()

	fmt.Fprintln(a.Out, "DEBUG: Running PerformLogin")

	scope := []string{"openid", "profile", "email"}
	if len(a.ExtraScope) > 0 {
		scope = append(scope, a.ExtraScope...)
	}
	
	fmt.Fprintln(a.Out, "DEBUG: scopes: %v", scope)

	conf := &oauth2.Config{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Endpoint:     a.Endpoint,
		Scopes:       scope,
	}
	
	fmt.Fprintln(a.Out, "DEBUG: skip browser? %v", a.SkipBrowser)

	if !a.SkipBrowser {
		// Attempt to receive the authorization code via redirect URL
		if ln, port, err := getListener(a, callbackPort); err == nil {
			defer ln.Close()
			fmt.Fprintln(a.Out, "DEBUG: Browser opened, listening to port %v", port)
			// open a web browser and listen on the redirect URL port
			conf.RedirectURL = fmt.Sprintf("http://localhost:%d", port)
			aud := oauth2.SetAuthURLParam("audience", a.Audience)
			var opts []oauth2.AuthCodeOption
			opts = append(opts, oauth2.AccessTypeOffline)
			opts = append(opts, promptConsent)
			opts = append(opts, aud)
			for key, value := range a.ExtraAuthParams {
				opts = append(opts, oauth2.SetAuthURLParam(key, value))
			}
			url := conf.AuthCodeURL("state", opts...)
			if err := a.OpenBrowser(url); err == nil {
				if code, err := handleCodeResponse(ln); err == nil {
					token, err := conf.Exchange(oauth2.NoContext, code)
					if err != nil {
						return nil, err
					}
					return conf.TokenSource(oauth2.NoContext, token), nil
				}
			}
		} else {
			fmt.Fprintln(a.Out, "DEBUG: Error opening browser: %v", err)
		}
	}

	// If we can't or shouldn't automatically retrieve the code via browser,
	// default to a command line prompt.
	code, err := a.codeViaPrompt(conf)
	if err != nil {
		return nil, err
	}

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}
	return conf.TokenSource(oauth2.NoContext, token), nil
}

func (a *LoginAgent) codeViaPrompt(conf *oauth2.Config) (string, error) {
	// Direct the user to our login portal
	conf.RedirectURL = redirectURIAuthCodeInTitleBar
	aud := oauth2.SetAuthURLParam("audience", a.Audience)
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, promptConsent, aud)
	fmt.Fprintln(a.Out, "Please visit the following URL and complete the authorization dialog:")
	fmt.Fprintf(a.Out, "%v\n", url)

	// Receive the authorization_code in response
	fmt.Fprintln(a.Out, "Authorization code:")
	var code string
	if _, err := fmt.Fscan(a.In, &code); err != nil {
		return "", err
	}

	return code, nil
}

func getListener(a *LoginAgent, port int) (net.Listener, int, error) {
	laddr := net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} // port: 0 == find free port
	fmt.Fprintln(a.Out, "DEBUG: getListener -- laddr %v", laddr)
	ln, err := net.ListenTCP("tcp4", &laddr)
	fmt.Fprintln(a.Out, "DEBUG: getListener -- ln %v", ln)
	fmt.Fprintln(a.Out, "DEBUG: getListener -- ln.Addr() %v", ln.Addr())
	fmt.Fprintln(a.Out, "DEBUG: getListener -- err %v", err)
	if err != nil {
		return nil, 0, err
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

func handleCodeResponse(ln net.Listener) (string, error) {
	conn, err := ln.Accept()
	if err != nil {
		return "", err
	}

	srvConn := httputil.NewServerConn(conn, nil)
	defer srvConn.Close()

	req, err := srvConn.Read()
	if err != nil {
		return "", err
	}

	code := req.URL.Query().Get("code")

	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Close:         true,
		ContentLength: -1, // designates unknown length
	}
	defer srvConn.Write(req, resp)

	// If the code couldn't be obtained, inform the user via the browser and
	// return an error.
	// TODO i18n?
	if code == "" {
		err := fmt.Errorf("Code not present in response: %s", req.URL.String())
		resp.Body = getResponseBody("ERROR: Authentication code not present in response, please retry with --no-browser.")
		return "", err
	}

	resp.Body = getResponseBody("Success! You may now close your browser.")
	return code, nil
}

func greetAnyRequest(ln net.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}

	srvConn := httputil.NewServerConn(conn, nil)
	defer srvConn.Close()

	req, err := srvConn.Read()
	if err != nil {
		return err
	}

	fmt.Println("Received request %v", req)

	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Close:         true,
		ContentLength: -1, // designates unknown length
	}
	defer srvConn.Write(req, resp)

	resp.Body = getResponseBody("Hello! Server test worked successfully!")
	return nil
}

// turn a string into an io.ReadCloser as required by an http.Response
func getResponseBody(body string) io.ReadCloser {
	reader := strings.NewReader(body)
	return ioutil.NopCloser(reader)
}
