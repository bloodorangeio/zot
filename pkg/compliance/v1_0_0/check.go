//nolint (dupl)
package v1_0_0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"gopkg.in/resty.v1"
)

type (
	Request struct {
		*resty.Request
	}

	Response struct {
		*resty.Response
	}

	Client struct {
		*resty.Client
		Config struct {
			Address string
			Namespace string
			Auth   struct {
				Basic struct {
					Username string
					Password string
				}
			}
		}
	}
)

func (client *Client) NewRequest() *Request {
	restyRequest := client.Client.NewRequest()
	return &Request{restyRequest}
}

func (req *Request) Execute(method, url string) (*Response, error) {
	restyResponse, err := req.Request.Execute(method, url)
	if err != nil {
		return nil, err
	}
	resp := &Response{restyResponse}
	return resp, err
}

func (client *Client) Do(method, path string) (*Response, error) {
	path = strings.Replace(path, ":namespace", client.Config.Namespace, -1)
	url := fmt.Sprintf("%s%s", client.Config.Address, path)

	req := client.NewRequest()
	resp, err := req.Execute(method, url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() == 401 {
		authInfoMap := getAuthInfoMap(resp.Header())
		authUrl := buildAuthUrlString(authInfoMap)
		token := getToken(authUrl, client.Config.Auth.Basic.Username, client.Config.Auth.Basic.Password)
		client.SetAuthToken(token)
		resp, err = req.Execute(method, url)
		return resp, err
	}

	return resp, err
}

func getAuthInfoMap(header map[string][]string) map[string]string {
	authInfo := header["Www-Authenticate"][0]
	re := regexp.MustCompile(`([a-zA-z]+)="(.+?)"`)
	ary := re.FindAllStringSubmatch(authInfo, -1)
	m := make(map[string]string)
	for i := 0; i < len(ary); i++ {
		m[ary[i][1]] = ary[i][2]
	}
	return m
}

func buildAuthUrlString(m map[string]string) string {
	realm := m["realm"]
	delete(m, "realm")
	var prms []string
	for k, v := range m {
		prms = append(prms, fmt.Sprintf("%s=%s", k, v))
	}
	paramString := strings.Join(prms, "&")
	authUrl := fmt.Sprintf("%s?%s", realm, paramString)
	return authUrl
}

func getToken(url, user, pass string) string {
	authReq := resty.R()
	authReq.SetBasicAuth(user, pass)
	authResp, _ := authReq.Get(url)
	re := regexp.MustCompile(`"token":"(.+?)"`)
	token := re.FindStringSubmatch(authResp.String())[1]
	return token
}

func CheckWorkflows(t *testing.T, config *compliance.Config) {
	if config == nil || config.Address == "" || config.Namespace == "" {
		panic("insufficient config")
	}

	if config.OutputJSON {
		outputJSONEnter()
		defer outputJSONExit()
	}

	client := &Client{}
	client.Client = resty.New()
	client.Config.Address = config.Address
	client.Config.Namespace = config.Namespace
	client.Config.Auth.Basic.Username = config.Username
	client.Config.Auth.Basic.Password = config.Password

	fmt.Println("------------------------------")
	fmt.Println("Checking for v1.0.0 compliance")
	fmt.Println("------------------------------")

	Convey("Make API calls to the controller", t, func(c C) {
		Convey("Check version", func() {
			Print("\nCheck version")
			resp, err := client.Do(resty.MethodGet, "/v2/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			Print("\nGet repository catalog")
			resp, err := client.Do(resty.MethodGet, "/v2/_catalog")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, api.DefaultMediaType)
			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			//So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			resp, err = client.Do(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			//resp, err = client.Do(resty.MethodPost, "/v2/a/b/c/d/blobs/uploads/")
			//Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 202)

			// TODO: Add setResult to custom Response
			//respx, err := client.NewRequest().SetResult(&api.RepositoryList{}).Get(config.Address + "/v2/_catalog")
			//Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			//So(err, ShouldBeNil)
			//So(respx.StatusCode(), ShouldEqual, 200)
			//So(respx.String(), ShouldNotBeEmpty)
			//r := respx.Result().(*api.RepositoryList)
			//So(len(r.Repositories), ShouldBeGreaterThan, 0)
			//So(r.Repositories[0], ShouldEqual, "a/b/c/d")
			//So(r.Repositories[1], ShouldEqual, "z")
		})

		Convey("Get images in a repository", func() {
			Print("\nGet images in a repository")
			// non-existent repository should fail
			resp, err := client.Do(resty.MethodGet, "/v2/this/cannot/exist/tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			//TODO: Check that number of blobs has increased by 1 after upload
			// after newly created upload should succeed
			resp, err = client.Do(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = client.Do(resty.MethodGet, "/v2/:namespace/tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
		})

		Convey("Monolithic blob upload", func() {
			Print("\nMonolithic blob upload")
			resp, err := client.Do(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			//resp, err := newReq().Exec(resty.MethodPost, config.Address + prefix + "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)
			u, err := url.Parse(loc)
			So(err, ShouldBeNil)

			//TODO:
			resp, err = client.Do(resty.MethodGet, u.Path)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = client.Do(resty.MethodGet, "/v2/:namespace/tags/list")
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + prefix + "tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = client.Do(resty.MethodPut,  u.Path)
			//resp, err = newReq().Exec(resty.MethodPut, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = client.Do(resty.MethodPut, fmt.Sprintf("%s?digest=%s", u.Path, digest))
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			respx, err := resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(u.Path)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			respx, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			blobLoc := respx.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(respx.Header().Get("Content-Length"), ShouldEqual, "0")
			So(respx.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = client.Do(resty.MethodGet,  loc)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = client.Do(resty.MethodGet,  blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			Print("\nMonolithic blob upload with multiple name components")
			resp, err := client.Do(resty.MethodPost,  "1/repo2/repo3/blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = client.Do(resty.MethodGet,  "1/repo2/repo3/tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = client.Do(resty.MethodPut,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			respx, err := resty.R().SetQueryParam("digest", digest.String()).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			respx, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			respx, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			blobLoc := respx.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(respx.Header().Get("Content-Length"), ShouldEqual, "0")
			So(respx.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = client.Do(resty.MethodGet,  blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			Print("\nChunked blob upload")
			resp, err := client.Do(resty.MethodPost,  "/v2/blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			respx, err := resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			respx, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 400)
			So(respx.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes()))
			respx, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			blobLoc := respx.Header().Get("Location")
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(respx.Header().Get("Content-Length"), ShouldEqual, "0")
			So(respx.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = client.Do(resty.MethodGet,  blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			Print("\nChunked blob upload with multiple name components")
			resp, err := client.Do(resty.MethodPost,  "4/repo5/repo6/blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			respx, err := resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			respx, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 400)
			So(respx.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes()))
			respx, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			blobLoc := respx.Header().Get("Location")
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(respx.Header().Get("Content-Length"), ShouldEqual, "0")
			So(respx.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = client.Do(resty.MethodGet,  blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			Print("\nCreate and delete uploads")
			// create a upload
			resp, err := client.Do(resty.MethodPost,   "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			resp, err = client.Do(resty.MethodDelete,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete blobs", func() {
			Print("\nCreate and delete blobs")
			// create a upload
			resp, err := client.Do(resty.MethodPost,   "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			respx, err := resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			blobLoc := respx.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(respx.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			resp, err = client.Do(resty.MethodDelete,  blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Manifests", func() {
			Print("\nManifests")
			// create a blob/layer
			resp, err := client.Do(resty.MethodPost,  "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = client.Do(resty.MethodGet,  loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			respx, err := resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			blobLoc := respx.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(respx.Header().Get("Content-Length"), ShouldEqual, "0")
			So(respx.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// create a manifest
			m := ispec.Manifest{Layers: []ispec.Descriptor{{Digest: digest}}}
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			respx, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(config.Address + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", respx.StatusCode(), respx, respx.Header())
			So(err, ShouldBeNil)
			So(respx.StatusCode(), ShouldEqual, 201)
			d := respx.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = client.Do(resty.MethodHead,  "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = client.Do(resty.MethodGet,  "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = client.Do(resty.MethodHead,  "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = client.Do(resty.MethodGet,  "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest
			resp, err = client.Do(resty.MethodDelete,  "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			// delete again should fail
			resp, err = client.Do(resty.MethodDelete,  "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			resp, err = client.Do(resty.MethodHead,  "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = client.Do(resty.MethodGet,  "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = client.Do(resty.MethodHead,  "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = client.Do(resty.MethodGet,  "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
		})
	})
}

var (
	old  *os.File
	r    *os.File
	w    *os.File
	outC chan string
)

func outputJSONEnter() {
	// this env var instructs goconvey to output results to JSON (stdout)
	os.Setenv("GOCONVEY_REPORTER", "json")

	// stdout capture copied from: https://stackoverflow.com/a/29339052
	old = os.Stdout
	// keep backup of the real stdout
	r, w, _ = os.Pipe()
	outC = make(chan string)
	os.Stdout = w

	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()
}

func outputJSONExit() {
	// back to normal state
	w.Close()
	os.Stdout = old // restoring the real stdout
	out := <-outC

	// The output of JSON is combined with regular output, so we capture everything between
	// the special strings reporting.OpenJSON and reporting.CloseJson.
	rString := fmt.Sprintf("(?s)%s(.*),.?%s", reporting.OpenJson, reporting.CloseJson)
	re := regexp.MustCompile(rString)
	matchArray := re.FindStringSubmatch(out)
	rawJSON := fmt.Sprintf("[%s]", matchArray[1])

	rawJSONMinified := validateMinifyRawJSON(rawJSON)
	fmt.Println(rawJSONMinified)
}

func validateMinifyRawJSON(rawJSON string) string {
	var j interface{}
	err := json.Unmarshal([]byte(rawJSON), &j)
	if err != nil {
		panic(err)
	}
	rawJSONBytesMinified, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	return string(rawJSONBytesMinified)
}
