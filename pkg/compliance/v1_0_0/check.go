//nolint (dupl)
package v1_0_0

import (
	"bytes"
	"encoding/json"
	"fmt"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"io"
	"net/url"

	//"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance"
	"github.com/bloodorangeio/reggie"
	//godigest "github.com/opencontainers/go-digest"
	//ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"gopkg.in/resty.v1"
)

func CheckWorkflows(t *testing.T, config *compliance.Config) {
	if config == nil || config.Address == "" || config.Namespace == "" {
		panic("insufficient config")
	}

	if config.OutputJSON {
		outputJSONEnter()
		defer outputJSONExit()
	}

	client := &reggie.Client{}
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
			req := client.NewRequest(resty.MethodGet, "/v2/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			Print("\nGet repository catalog")
			req := client.NewRequest(resty.MethodGet, "/v2/_catalog")
			resp, err := client.Do(req)
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
			req = client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			//resp, err = client.Do(resty.MethodPost, "/v2/a/b/c/d/blobs/uploads/")
			//Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 202)

			// TODO: Add setResult to custom Response
			//resp, err := client.NewRequest().SetResult(&api.RepositoryList{}).Get(config.Address + "/v2/_catalog")
			//Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 200)
			//So(resp.String(), ShouldNotBeEmpty)
			//r := resp.Result().(*api.RepositoryList)
			//So(len(r.Repositories), ShouldBeGreaterThan, 0)
			//So(r.Repositories[0], ShouldEqual, "a/b/c/d")
			//So(r.Repositories[1], ShouldEqual, "z")
		})

		Convey("Get images in a repository", func() {
			Print("\nGet images in a repository")
			// non-existent repository should fail
			req := client.NewRequest(resty.MethodGet, "/v2/this/cannot/exist/tags/list")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			//TODO: Check that number of blobs has increased by 1 after upload
			// after newly created upload should succeed
			req = client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			req = client.NewRequest(resty.MethodGet, "/v2/:namespace/tags/list")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
		})

		Convey("Monolithic blob upload", func() {
			Print("\nMonolithic blob upload")
			req := client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err := client.Do(req)
			//resp, err := newReq().Exec(resty.MethodPost, config.Address + prefix + "blobs/uploads/")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)
			u, err := url.Parse(loc)
			So(err, ShouldBeNil)

			//TODO:
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			req = client.NewRequest(resty.MethodGet, "/v2/:namespace/tags/list")
			resp, err = client.Do(req)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + prefix + "tags/list")
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			req = client.NewRequest(resty.MethodPut, u.Path)
			resp, err = client.Do(req)
			//resp, err = newReq().Exec(resty.MethodPut, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			req = client.NewRequest(resty.MethodPut, fmt.Sprintf("%s?digest=%s", u.Path, digest))
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(content)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			//resp, err = newReq().Exec(resty.MethodGet, config.Address + loc)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			u, err = url.Parse(blobLoc)
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			Print("\nMonolithic blob upload with multiple name components")
			req := client.NewRequest(resty.MethodPost, "/v2/1/repo2/repo3/blobs/uploads/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)

			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			req = client.NewRequest(resty.MethodGet, "/v2/1/repo2/repo3/tags/list")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			req = client.NewRequest(resty.MethodPut, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(content)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			u, err = url.Parse(blobLoc)
			// blob reference should be accessible
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			Print("\nChunked blob upload")
			req := client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			//write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(resty.MethodPatch, u.Path)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(resty.MethodPatch, u.Path)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			resp, err = client.Do(req)
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
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Range", contentRange)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(chunk2)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			bu, err := url.Parse(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			req = client.NewRequest(resty.MethodGet, bu.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			Print("\nChunked blob upload with multiple name components")
			req := client.NewRequest(resty.MethodPost, "/v2/:namespace/4/repo5/repo6/blobs/uploads/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(resty.MethodPatch, u.Path)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(resty.MethodPatch, u.Path)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			resp, err = client.Do(req)
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
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Range", contentRange)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(chunk2)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			bu, err := url.Parse(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			req = client.NewRequest(resty.MethodGet, bu.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			Print("\nCreate and delete uploads")
			// create a upload
			req := client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			req = client.NewRequest(resty.MethodDelete, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete blobs", func() {
			Print("\nCreate and delete blobs")
			// create a upload
			req := client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(content)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			bu, err := url.Parse(blobLoc)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			req = client.NewRequest(resty.MethodDelete, bu.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Manifests", func() {
			Print("\nManifests")
			// create a blob/layer
			req := client.NewRequest(resty.MethodPost, "/v2/:namespace/blobs/uploads/")
			resp, err := client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)

			req = client.NewRequest(resty.MethodGet, u.Path)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			req = client.NewRequest(resty.MethodPut, u.Path)
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(content)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			//bu, err := url.Parse(blobLoc)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// create a manifest
			m := ispec.Manifest{Layers: []ispec.Descriptor{{Digest: digest}}}
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			req = client.NewRequest(resty.MethodPut, "/v2/:namespace/manifests/test:1.0")
			req.SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			req.SetBody(content)
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			req = client.NewRequest(resty.MethodHead, "/v2/:namespace/manifests/test:1.0")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			req = client.NewRequest(resty.MethodGet, "/v2/:namespace/manifests/test:1.0")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			req = client.NewRequest(resty.MethodHead, "/v2/:namespace/manifests/"+digest.String())
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			req = client.NewRequest(resty.MethodGet, "/v2/:namespace/manifests/"+digest.String())
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest
			req = client.NewRequest(resty.MethodDelete, "/v2/:namespace/manifests/test:1.0")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			// delete again should fail
			req = client.NewRequest(resty.MethodDelete, "/v2/:namespace/manifests/"+digest.String())
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			req = client.NewRequest(resty.MethodHead, "/v2/:namespace/manifests/test:1.0")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			req = client.NewRequest(resty.MethodGet, "/v2/:namespace/manifests/test:1.0")
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			req = client.NewRequest(resty.MethodHead, "/v2/:namespace/manifests/"+digest.String())
			resp, err = client.Do(req)
			Printf("\nResponse code: %v\nResponse body: %v\nResponse Header: %v\n", resp.StatusCode(), resp, resp.Header())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			req = client.NewRequest(resty.MethodGet, "/v2/:namespace/manifests/"+digest.String())
			resp, err = client.Do(req)
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
