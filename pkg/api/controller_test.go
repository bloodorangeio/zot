package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	cmAuth "github.com/chartmuseum/auth"
	vldap "github.com/nmcclain/ldap"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	BaseURL1              = "http://127.0.0.1:8081"
	BaseURL2              = "http://127.0.0.1:8082"
	BaseURL3              = "http://127.0.0.1:8083"
	BaseSecureURL2        = "https://127.0.0.1:8082"
	SecurePort1           = "8081"
	SecurePort2           = "8082"
	SecurePort3           = "8083"
	username              = "test"
	passphrase            = "test"
	ServerCert            = "../../test/data/server.cert"
	ServerKey             = "../../test/data/server.key"
	CACert                = "../../test/data/ca.crt"
	BearerCert            = "../../test/data/bearer-test.crt"
	BearerKey             = "../../test/data/bearer-test.key"
	AuthorizedNamespace   = "org1/repo1"
	UnauthorizedNamespace = "fortknox/notallowed"
)

func makeHtpasswdFile() string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte("test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n")
	if err := ioutil.WriteFile(f.Name(), content, 0644); err != nil {
		panic(err)
	}

	return f.Name()
}

func TestNew(t *testing.T) {
	Convey("Make a new controller", t, func() {
		config := api.NewConfig()
		So(config, ShouldNotBeNil)
		So(api.NewController(config), ShouldNotBeNil)
	})
}

//TODO write test
//401 ? get token, retry & expect 200

//TODO write test
//401 ? get valid token without required scope, retry & expect 401

//TODO: write test
func TestBearerAuth(t *testing.T) {
	Convey("test", t, func() {
		cmTokenGenerator, err := cmAuth.NewTokenGenerator(&cmAuth.TokenGeneratorOptions{
			// TODO: this cert+path needs to be configurable provisioned on Helm install
			PrivateKeyPath: "../../test/data/bearer-test.key",
			Audience:       "Zot Registry",
			Issuer:         "Zot",
			AddKIDHeader:   true,
		})
		if err != nil {
			panic(err)
		}

		authTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/token":
				scope := r.URL.Query().Get("scope")
				parts := strings.Split(scope, ":")
				if len(parts) != 3 {
					fmt.Println("Error 2:")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				name := parts[1]

				var actions []string
				if name != UnauthorizedNamespace {
					actions = []string{cmAuth.PullAction}
				}
				access := []cmAuth.AccessEntry{
					{
						Name:    name,
						Type:    "repository",
						Actions: actions,
					},
				}

				token, err := cmTokenGenerator.GenerateToken(access, time.Minute*1)
				if err != nil {
					fmt.Println("Error 3:")
					fmt.Println(err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"access_token": "%s"}`, token)
			}
		}))
		defer authTestServer.Close()
		resp, _ := resty.R().Get(authTestServer.URL + "/auth/token?service=staging.bundle.bar&scope=repository:org1/repo1:pull")
		fmt.Println(resp)
		resp, _ = resty.R().Get(authTestServer.URL + "/auth/token?service=staging.bundle.bar&scope=repository:fortknox/notallowed:pull")
		fmt.Println(resp)

		config := api.NewConfig()
		config.HTTP.Port = SecurePort3

		u, err := url.Parse(authTestServer.URL)
		config.HTTP.Auth = &api.AuthConfig{
			Bearer: &api.BearerConfig{
				Cert: BearerCert,
				Realm: authTestServer.URL + "/auth/token",
				Service: u.Host,
			},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL3)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		resp, err = resty.R().Get(BaseURL3 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		resp, err = resty.R().Get(authTestServer.URL + "/auth/token?service=staging.bundle.bar&scope=repository:org1/repo1:pull")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		resp, err = resty.R().Get(authTestServer.URL + "/auth/token?service=staging.bundle.bar&scope=repository:fortknox/notallowed:pull")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)


		//var e api.Error
		//err = json.Unmarshal(resp.Body(), &e)
		//So(err, ShouldBeNil)

		//DONE/////////1. set up auth server
		//DONE/////////  1a. Generates token from private key file using cm-Auth token generator that uses testPrivateKey file
		//DONE/////////			see bundlebar auth server
		//DONE/////////	1b. Just returns a token in application/json.
		//DONE/////////		{ "access_token": "<jwt>" }
		//DONE/////////		extract scope query param, use to determine name + action to use in []AccessEntry passed to tokenGenerator.GenerateToken()
		//DONE/////////		Always returns 200 & valid JWT; sometimes JWT does not contain requested scope
		//DONE/////////	1c.	actions should be empty in valid JWT token if repo is fortknox/notallowed
		//DONE/////////
		//2. Set up a Zot using Bearer Auth, referencing testPublicKey to construct controller on port 8083
		//		(or whatever next port is not in use)
		//
		//3. Run tests similarly to BasicAuth tests
		//		Check for 401 vs 200 where expected (401 for forknox/notallowed
		//		verify code coverage
	})
}
func TestBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		config := api.NewConfig()
		config.HTTP.Port = SecurePort1
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSWithBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.TLS = &api.TLSConfig{
			Cert: ServerCert,
			Key:  ServerKey,
		}
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without creds, should get access error
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSWithBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		config.HTTP.TLS = &api.TLSConfig{
			Cert: ServerCert,
			Key:  ServerKey,
		}
		config.HTTP.AllowReadAccess = true

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without creds, should still be allowed to access
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// without creds, writes should fail
		resp, err = resty.R().Post(BaseSecureURL2 + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
	})
}

func TestTLSMutualAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, should get conn error
		_, err = resty.R().Get(BaseSecureURL2)
		So(err, ShouldNotBeNil)

		// with creds but without certs, should get conn error
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(err, ShouldNotBeNil)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSMutualAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}
		config.HTTP.AllowReadAccess = true

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, reads are allowed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with creds but without certs, reads are allowed
		resp, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// without creds, writes should fail
		resp, err = resty.R().Post(BaseSecureURL2 + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSMutualAndBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, should fail
		_, err = resty.R().Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should get access error
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSMutualAndBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}
		config.HTTP.AllowReadAccess = true

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, should fail
		_, err = resty.R().Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, reads should succeed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with only client certs, writes should fail
		resp, err = resty.R().Post(BaseSecureURL2 + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

const (
	LDAPAddress      = "127.0.0.1"
	LDAPPort         = 9636
	LDAPBaseDN       = "ou=test"
	LDAPBindDN       = "cn=reader," + LDAPBaseDN
	LDAPBindPassword = "bindPassword"
)

type testLDAPServer struct {
	server *vldap.Server
	quitCh chan bool
}

func newTestLDAPServer() *testLDAPServer {
	l := &testLDAPServer{}
	quitCh := make(chan bool)
	server := vldap.NewServer()
	server.QuitChannel(quitCh)
	server.BindFunc("", l)
	server.SearchFunc("", l)
	l.server = server
	l.quitCh = quitCh

	return l
}

func (l *testLDAPServer) Start() {
	addr := fmt.Sprintf("%s:%d", LDAPAddress, LDAPPort)

	go func() {
		if err := l.server.ListenAndServe(addr); err != nil {
			panic(err)
		}
	}()

	for {
		_, err := net.Dial("tcp", addr)
		if err == nil {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (l *testLDAPServer) Stop() {
	l.quitCh <- true
}

func (l *testLDAPServer) Bind(bindDN, bindSimplePw string, conn net.Conn) (vldap.LDAPResultCode, error) {
	if bindDN == "" || bindSimplePw == "" {
		return vldap.LDAPResultInappropriateAuthentication, errors.New("ldap: bind creds required")
	}

	if (bindDN == LDAPBindDN && bindSimplePw == LDAPBindPassword) ||
		(bindDN == fmt.Sprintf("cn=%s,%s", username, LDAPBaseDN) && bindSimplePw == passphrase) {
		return vldap.LDAPResultSuccess, nil
	}

	return vldap.LDAPResultInvalidCredentials, errors.New("ldap: invalid credentials")
}

func (l *testLDAPServer) Search(boundDN string, req vldap.SearchRequest,
	conn net.Conn) (vldap.ServerSearchResult, error) {
	check := fmt.Sprintf("(uid=%s)", username)
	if check == req.Filter {
		return vldap.ServerSearchResult{
			Entries: []*vldap.Entry{
				{DN: fmt.Sprintf("cn=%s,%s", username, LDAPBaseDN)},
			},
			ResultCode: vldap.LDAPResultSuccess,
		}, nil
	}

	return vldap.ServerSearchResult{}, nil
}

func TestBasicAuthWithLDAP(t *testing.T) {
	Convey("Make a new controller", t, func() {
		l := newTestLDAPServer()
		l.Start()
		defer l.Stop()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort1
		config.HTTP.Auth = &api.AuthConfig{
			LDAP: &api.LDAPConfig{
				Insecure:      true,
				Address:       LDAPAddress,
				Port:          LDAPPort,
				BindDN:        LDAPBindDN,
				BindPassword:  LDAPBindPassword,
				BaseDN:        LDAPBaseDN,
				UserAttribute: "uid",
			},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}
