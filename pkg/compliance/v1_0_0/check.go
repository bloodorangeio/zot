//nolint (dupl)
//package v1_0_0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
  "regexp"
  "strings"

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
    Token string
  }
)

func newReq() *ZotRequest {
  restyRequest := resty.R()
  return &ZotRequest{restyRequest, ""}
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

func (r *ZotRequest) Exec(method string, url string) (*resty.Response, error) {
  resp, err := r.Execute(method, url)
  if resp.StatusCode() == 401 {
    kv := getAuthInfoMap(resp.Header())
    authUrl := buildAuthUrlString(kv)
    fmt.Printf("\nurl: %s", authUrl)
    ar := resty.R()
    ar.SetBasicAuth("pmengelbert", "IxmSUToStj3xDM7URoAZm+AUBKN9RW9ksFeBnk87s/hQcLDKPPyd+oStCHGuHaw6+1nsQ1RT/QwH+SY136ByrM1t9a5vBrNWDf8dBEr7d7Q=")
    authResp, _ := ar.Execute(method, authUrl)
    re3 := regexp.MustCompile(`"token":"(.+?)"`)
    tstring := re3.FindStringSubmatch(authResp.String())[1]
    //fmt.Printf("\nauthResp: %v", authResp.String())
    //fmt.Printf("\ntoken: %s", tstring)
    r.SetAuthToken(tstring)
    resp3, _ := r.Execute(method, url)
    //fmt.Printf("\nresp3: %s", resp3.String())
    return resp3, err
  } else {
    return resp, err
  }
}

func CheckWorkflows(t *testing.T, config *compliance.Config) {
	if config == nil || config.Address == "" || config.Port == "" || config.Namespace == "" {
		panic("insufficient config")
	}

  protocol := "http"
  if config.UseHTTPS {
    protocol = protocol + "s"
  }
  baseURL := fmt.Sprintf("%s://%s:%s", protocol, config.Address, config.Port)
  prefix := fmt.Sprintf("/v2/%s/", config.Namespace)

	fmt.Println("------------------------------")
	fmt.Println("Checking for v1.0.0 compliance")
	fmt.Println("------------------------------")

	Convey("Make API calls to the controller", t, func(c C) {
		Convey("Check version", func() {
			Print("\nCheck version")
			resp, err := resty.R().Get(baseURL + "/v2/")
      resp, _ = newReq().Exec("GET", baseURL + "/v2/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			Print("\nGet repository catalog")
			resp, err := resty.R().Get(baseURL + "/v2/_catalog")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, api.DefaultMediaType)
			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/z/blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/a/b/c/d/blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().SetResult(&api.RepositoryList{}).Get(baseURL + "/v2/_catalog")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
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
			resp, err := resty.R().Get(baseURL + prefix + "tags/list")
      resp, _ = newReq().Exec("GET", baseURL + prefix + "tags/list")
      Printf("\nResponse Code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + prefix + "blobs/uploads/")
      resp, _ = newReq().Exec("POST", baseURL + prefix + "tags/list")
      Printf("\nResponse Code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().Get(baseURL + prefix + "tags/list")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
		})

		Convey("Monolithic blob upload", func() {
			Print("\nMonolithic blob upload")
			resp, err := resty.R().Post(baseURL + prefix + "blobs/uploads/")
      resp, _ = newReq().Exec("GET", baseURL + prefix + "tags/list")
      Printf("\nResponse Code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(baseURL + prefix + "tags/list")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(baseURL + blobLoc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			Print("\nMonolithic blob upload with multiple name components")
			resp, err := resty.R().Post(baseURL + prefix + "1/repo2/repo3/blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(baseURL + prefix + "1/repo2/repo3/tags/list")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(baseURL + blobLoc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			Print("\nChunked blob upload")
			resp, err := resty.R().Post(baseURL + prefix + "blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
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
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
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
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(baseURL + blobLoc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			Print("\nChunked blob upload with multiple name components")
			resp, err := resty.R().Post(baseURL + prefix + "4/repo5/repo6/blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
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
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
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
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(baseURL + blobLoc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			Print("\nCreate and delete uploads")
			// create a upload
			resp, err := resty.R().Post(baseURL + prefix + "blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			resp, err = resty.R().Delete(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete blobs", func() {
			Print("\nCreate and delete blobs")
			// create a upload
			resp, err := resty.R().Post(baseURL + prefix + "blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			resp, err = resty.R().Delete(baseURL + blobLoc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Manifests", func() {
			Print("\nManifests")
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + prefix + "blobs/uploads/")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(baseURL + loc)
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
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
				SetBody(content).Put(baseURL + prefix + "manifests/test:1.0")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = resty.R().Head(baseURL + prefix + "manifests/test:1.0")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(baseURL + prefix + "manifests/test:1.0")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + prefix + "manifests/" + digest.String())
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(baseURL + prefix + "manifests/" + digest.String())
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest
			resp, err = resty.R().Delete(baseURL + prefix + "manifests/test:1.0")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			// delete again should fail
			resp, err = resty.R().Delete(baseURL + prefix + "manifests/" + digest.String())
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + prefix + "manifests/test:1.0")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + prefix + "manifests/test:1.0")
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + prefix + "manifests/" + digest.String())
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + prefix + "manifests/" + digest.String())
      Printf("\nResponse body: %v\nResponse Header: %v\n", resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
		})
	})
}

func main() {
  protocol := "https"
  baseURL := fmt.Sprintf("%s://%s:%s", protocol, "quay.io", "443")
  _, _ = newReq().Exec("GET", baseURL + "/v2/")
}
