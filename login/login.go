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
	"context"
	"crypto/tls"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
	"math/big"

	"github.com/toqueteos/webbrowser"
	"golang.org/x/oauth2"
)

const redirectURIAuthCodeInTitleBar = "urn:ietf:wg:oauth:2.0:oob"

const serverOverTLS = false

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

type ServerTestHandler struct {
	Stop chan bool;
}

func (h *ServerTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("Hello! Server test worked successfully!\n"))
    h.Stop <- true
}

func GetCertificate() func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    opts := Certopts{
        RsaBits:   2048,
        Host:      "localhost",
        ValidFrom: time.Now(),
    }
    cert, err := generate(opts)
    return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        if err != nil {
            return nil, err
        }
        return cert, err
    }
}

type Certopts struct {
    RsaBits   int
    Host      string
    IsCA      bool
    ValidFrom time.Time
    ValidFor  time.Duration
}

func generate(opts Certopts) (*tls.Certificate, error) {

    priv, err := rsa.GenerateKey(rand.Reader, opts.RsaBits)
    if err != nil {
        return nil, err
    }

    notAfter := opts.ValidFrom.Add(opts.ValidFor)

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        return nil, err
    }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"Acme Co"},
        },
        NotBefore: opts.ValidFrom,
        NotAfter:  notAfter,

        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    hosts := strings.Split(opts.Host, ",")
    for _, h := range hosts {
        if ip := net.ParseIP(h); ip != nil {
            template.IPAddresses = append(template.IPAddresses, ip)
        } else {
            template.DNSNames = append(template.DNSNames, h)
        }
    }

    if opts.IsCA {
        template.IsCA = true
        template.KeyUsage |= x509.KeyUsageCertSign
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return nil, err
    }

    return &tls.Certificate{
        Certificate: [][]byte{derBytes},
        PrivateKey:  priv,
    }, nil
}

func (a *LoginAgent) PerformServerTest(callbackPort int) (error) {
	a.init()

	fmt.Fprintln(a.Out, "DEBUG: Running PerformServerTest")

	if ln, port, err := getListener(a, callbackPort); err == nil {
		defer ln.Close()
		fmt.Fprintln(a.Out, "Running server test on port %d (address: %v)", port, ln.Addr())

		done := make(chan bool, 1)
		srv := &http.Server{
			Handler: &ServerTestHandler{done},
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
            	GetCertificate: GetCertificate(),
			},
		}
		go func() {
			if serverOverTLS {
				fmt.Fprintln(a.Out, "Serving over TLS")
				if err := srv.ServeTLS(ln, "", ""); err != nil {
					fmt.Errorf("Serve err: %v\n")
				}
			} else {
				fmt.Fprintln(a.Out, "Serving over plain text")
				if err := srv.Serve(ln); err != nil {
					fmt.Errorf("Serve err: %v\n")
				}
			}
	    }()

	    <-done

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	    defer cancel()
	    if err := srv.Shutdown(ctx); err != nil {
	        fmt.Errorf("HTTP server error: %v\n", err)
	    }
	} else {
		return err
	}

	return nil
}

type CodeResponseHandler struct {
	Stop chan string;
}

func (h *CodeResponseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	w.Header().Set("Content-Type", "text/plain")

	// If the code couldn't be obtained, inform the user via the browser and return an error.
	// TODO i18n?
	if code == "" {
		fmt.Printf("Code not present in response: %s", r.URL.String())
		w.Write([]byte("ERROR: Authentication code not present in response, please retry with --no-browser.\n"))
	} else {
		w.Write([]byte("Success! You may now close your browser.\n"))
	}

    h.Stop <- code
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

			// open a web browser and listen on the redirect URL port
			if serverOverTLS {
				conf.RedirectURL = fmt.Sprintf("https://localhost:%d", port)
			} else {
				conf.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d", port)
			}
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
				done := make(chan string, 1)
				srv := &http.Server{
					Handler: &CodeResponseHandler{done},
					TLSConfig: &tls.Config{
						InsecureSkipVerify: true,
		            	GetCertificate: GetCertificate(),
					},
				}
				go func() {
					if serverOverTLS {
						fmt.Fprintln(a.Out, "Serving over TLS")
						if err := srv.ServeTLS(ln, "", ""); err != nil {
							fmt.Errorf("Serve err: %v\n")
						}
					} else {
						fmt.Fprintln(a.Out, "Serving over plain text")
						if err := srv.Serve(ln); err != nil {
							fmt.Errorf("Serve err: %v\n")
						}
					}
			    }()

			    code := <-done

				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			    defer cancel()
			    if err := srv.Shutdown(ctx); err != nil {
			        fmt.Errorf("HTTP server error: %v\n", err)
			    } else {
			    	fmt.Printf("CODE: %v\n", code)
					token, err := conf.Exchange(oauth2.NoContext, code)
					if err != nil {
						return nil, err
					}
					return conf.TokenSource(oauth2.NoContext, token), nil
				}
			}
		} else {
			return nil, err
		}
		/*if ln, port, err := getListener(a, callbackPort); err == nil {
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
		}*/
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

// turn a string into an io.ReadCloser as required by an http.Response
func getResponseBody(body string) io.ReadCloser {
	reader := strings.NewReader(body)
	return ioutil.NopCloser(reader)
}
