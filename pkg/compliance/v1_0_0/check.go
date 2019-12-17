//nolint (dupl)
package v1_0_0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

type (
	ZotRequest struct {
		*resty.Request
	}
)

func newReq() *ZotRequest {
	restyRequest := resty.R()
	return &ZotRequest{restyRequest}
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

func (r *ZotRequest) Exec(method, url, user, pass string) (*resty.Response, error) {
	resp, err := r.Execute(method, url)
	if resp.StatusCode() == 401 {
		authInfoMap := getAuthInfoMap(resp.Header())
		authUrl := buildAuthUrlString(authInfoMap)
		token := getToken(authUrl, user, pass)
		r.SetAuthToken(token)
		resp, err := r.Execute(method, url)
		return resp, err
	} else {
		return resp, err
	}
}

func CheckWorkflows(t *testing.T, config *compliance.Config) {
	if config == nil || config.Address == "" || config.Namespace == "" {
		panic("insufficient config")
	}

	if config.OutputJSON {
		outputJSONEnter()
		defer outputJSONExit()
	}

	prefix := fmt.Sprintf("/v2/%s/", config.Namespace)

	fmt.Println("------------------------------")
	fmt.Println("Checking for v1.0.0 compliance")
	fmt.Println("------------------------------")

	Convey("Make API calls to the controller", t, func(c C) {
		Convey("Check version", func() {
			Print("\nCheck version")
			resp, err := newReq().Exec(resty.MethodGet, config.Address+"/v2/", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			Print("\nGet repository catalog")
			//resp, err := resty.R().Get(config.Address + "/v2/_catalog")
			resp, err := newReq().Exec(resty.MethodGet, config.Address+"/v2/_catalog", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, api.DefaultMediaType)
			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			//resp, err = resty.R().Post(config.Address + "/v2/z/blobs/uploads/")
			resp, err = newReq().Exec(resty.MethodPost, config.Address+"/v2/z/blobs/uploads/", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			//resp, err = resty.R().Post(config.Address + "/v2/a/b/c/d/blobs/uploads/")
			resp, err = newReq().Exec(resty.MethodPost, config.Address+"/v2/a/b/c/d/blobs/uploads/", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().SetResult(&api.RepositoryList{}).Get(config.Address + "/v2/_catalog")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			r := resp.Result().(*api.RepositoryList)
			So(len(r.Repositories), ShouldBeGreaterThan, 0)
			So(r.Repositories[0], ShouldEqual, "a/b/c/d")
			So(r.Repositories[1], ShouldEqual, "z")
		})

		Convey("Get images in a repository", func() {
			Print("\nGet images in a repository")
			// non-existent repository should fail
			//resp, err := resty.R().Get(config.Address + prefix + "tags/list")
			resp, err := newReq().Exec(resty.MethodGet, config.Address+prefix+"tags/list", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			// after newly created upload should succeed
			//resp, err = resty.R().Post(config.Address + prefix + "blobs/uploads/")
			resp, err = newReq().Exec(resty.MethodPost, config.Address+prefix+"blobs/uploads/", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			//resp, err = resty.R().Get(config.Address + prefix + "tags/list")
			resp, err = newReq().Exec(resty.MethodGet, config.Address+prefix+"tags/list", config.Username, config.Password)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
		})

		Convey("Monolithic blob upload", func() {
			Print("\nMonolithic blob upload")
			resp, err := resty.R().Post(config.Address + prefix + "blobs/uploads/")
			//resp, err := newReq().Exec(resty.MethodPost, config.Address + prefix + "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(config.Address + loc)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(config.Address + prefix + "tags/list")
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + prefix + "tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(config.Address + loc)
			//resp, err = newReq().Exec(resty.MethodPut, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(config.Address + loc)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(config.Address + blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			Print("\nMonolithic blob upload with multiple name components")
			resp, err := resty.R().Post(config.Address + prefix + "1/repo2/repo3/blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(config.Address + prefix + "1/repo2/repo3/tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(config.Address + blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			Print("\nChunked blob upload")
			resp, err := resty.R().Post(config.Address + prefix + "blobs/uploads/")
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
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes()))
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(config.Address + blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			Print("\nChunked blob upload with multiple name components")
			resp, err := resty.R().Post(config.Address + prefix + "4/repo5/repo6/blobs/uploads/")
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
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes()))
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(config.Address + blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			Print("\nCreate and delete uploads")
			// create a upload
			resp, err := resty.R().Post(config.Address + prefix + "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			resp, err = resty.R().Delete(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete blobs", func() {
			Print("\nCreate and delete blobs")
			// create a upload
			resp, err := resty.R().Post(config.Address + prefix + "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			resp, err = resty.R().Delete(config.Address + blobLoc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Manifests", func() {
			Print("\nManifests")
			// create a blob/layer
			resp, err := resty.R().Post(config.Address + prefix + "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// create a manifest
			m := ispec.Manifest{Layers: []ispec.Descriptor{{Digest: digest}}}
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(config.Address + prefix + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = resty.R().Head(config.Address + prefix + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(config.Address + prefix + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(config.Address + prefix + "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(config.Address + prefix + "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest
			resp, err = resty.R().Delete(config.Address + prefix + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			// delete again should fail
			resp, err = resty.R().Delete(config.Address + prefix + "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			resp, err = resty.R().Head(config.Address + prefix + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(config.Address + prefix + "manifests/test:1.0")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(config.Address + prefix + "manifests/" + digest.String())
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(config.Address + prefix + "manifests/" + digest.String())
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

	// The output of JSON is combined with regular output, so we look for the
	// first occurrence of the "{" character and take everything after that
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
