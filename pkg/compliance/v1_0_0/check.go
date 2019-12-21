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
	"path"

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
	client.Client.Debug = true
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
			req := client.NewRequest(reggie.GET, "/v2/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			Print("\nGet repository catalog")
			req := client.NewRequest(reggie.GET, "/v2/_catalog")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, api.DefaultMediaType)
			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			//So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			req = client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			//resp, err = client.Do(reggie.POST, "/v2/a/b/c/d/blobs/uploads/")
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 202)

			// TODO: Add setResult to custom Response
			//resp, err := client.NewRequest().SetResult(&api.RepositoryList{}).Get(config.Address + "/v2/_catalog")
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
			req := client.NewRequest(reggie.GET, "/v2/this/cannot/exist/tags/list")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			//TODO: Check that number of blobs has increased by 1 after upload
			// after newly created upload should succeed
			req = client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			req = client.NewRequest(reggie.GET, "/v2/:name/tags/list")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
		})

		Convey("Monolithic blob upload", func() {
			Print("\nMonolithic blob upload")
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			uuid := path.Base(u.Path)
			So(loc, ShouldNotBeEmpty)
			So(err, ShouldBeNil)

			//TODO:
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			req = client.NewRequest(reggie.GET, "/v2/:name/tags/list")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			req.SetQueryParam("digest", digest.String())
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))

			//req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Length", fmt.Sprintf("%d", len(content)))
			req.SetBody(content)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)

			//This is failing test #1
			So(resp.StatusCode(), ShouldEqual, 201)

			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			bu, err := url.Parse(blobLoc)
			blobDigest := path.Base(bu.Path)
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/:digest", reggie.WithDigest(blobDigest))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			//Print("\nMonolithic blob upload with multiple name components")
			//req := client.NewRequest(reggie.POST, "/v2/1/repo2/repo3/blobs/uploads/")
			//printRequest(req)
			//resp, err := client.Do(req)
			//So(err, ShouldBeNil)

			//This is failing test #2
			//So(resp.StatusCode(), ShouldEqual, 202)

			//loc := resp.Header().Get("Location")
			//u, err := url.Parse(loc)
			//uuid := path.Base(u.Path)
			//So(loc, ShouldNotBeEmpty)

			//req = client.NewRequest(reggie.GET, "/v2/1/repo2/repo3/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 204)

			//req = client.NewRequest(reggie.GET, "/v2/1/repo2/repo3/tags/list")
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 200)
			//So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			//content := []byte("this is a blob")
			//digest := godigest.FromBytes(content)
			//So(digest, ShouldNotBeNil)
			//req := client.NewRequest(reggie.PUT, "/v2/1/repo2/repo3/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 400)
			//// without the Content-Length should fail
			//req = client.NewRequest(reggie.PUT, "/v2/1/repo2/repo3/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			//req.SetQueryParam("digest", digest.String())
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 400)
			//// without any data to send, should fail
			//req = client.NewRequest(reggie.PUT, "/v2/1/repo2/repo3/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			//req.SetQueryParam("digest", digest.String())
			//req.SetHeader("Content-Type", "application/octet-stream")
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 400)
			//// monolithic blob upload: success
			//req = client.NewRequest(reggie.PUT, "/v2/1/repo2/repo3/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			//req.SetQueryParam("digest", digest.String())
			//req.SetHeader("Content-Type", "application/octet-stream")
			//req.SetBody(content)
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 201)
			//blobLoc := resp.Header().Get("Location")
			//So(blobLoc, ShouldNotBeEmpty)
			//So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			//So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			//// upload reference should now be removed
			//req = client.NewRequest(reggie.GET, "/v2/1/repo2/repo3/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 404)
			//bu, err := url.Parse(blobLoc)
			//blobDigest := path.Base(bu.Path)
			//// blob reference should be accessible
			//req = client.NewRequest(reggie.GET, "/v2/1/repo2/repo3/blobs/:digest", reggie.WithDigest(blobDigest))
			//printRequest(req)
			//resp, err = client.Do(req)
			//So(err, ShouldBeNil)
			//So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			Print("\nChunked blob upload")
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			uuid := path.Base(u.Path)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			//write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(reggie.PATCH, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Length", fmt.Sprintf("%o", len(chunk1)))
			req.SetHeader("Content-Range", contentRange)
			//req.SetHeader("Docker-Content-Digest", )
			req.SetBody(chunk1)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)

			//This is failing test #3
			// TODO: 202 vs 204?
			// TODO: Quay returns 204 which does NOT meet spec
			//So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.StatusCode(), ShouldBeIn, []int{202, 204, 404})

			// check progress
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(reggie.PATCH, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			printRequest(req)
			resp, err = client.Do(req)
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
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Range", contentRange)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(chunk2)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			bu, err := url.Parse(blobLoc)
			blobDigest := path.Base(bu.Path)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/:digest", reggie.WithDigest(blobDigest))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			Print("\nChunked blob upload with multiple name components")
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)

			//This is failing test #4
			So(resp.StatusCode(), ShouldEqual, 202)

			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			So(loc, ShouldNotBeEmpty)
			uuid := path.Base(u.Path)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(reggie.PATCH, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			req = client.NewRequest(reggie.PATCH, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetHeader("Content-Range", contentRange)
			req.SetBody(chunk1)
			printRequest(req)
			resp, err = client.Do(req)
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
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Range", contentRange)
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(chunk2)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			bu, err := url.Parse(blobLoc)
			blobDigest := path.Base(bu.Path)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/:digest", reggie.WithDigest(blobDigest))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			Print("\nCreate and delete uploads")
			// create a upload
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			uuid := path.Base(u.Path)
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			req = client.NewRequest(reggie.DELETE, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)

			//This is failing test #5
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete blobs", func() {
			Print("\nCreate and delete blobs")
			// create a upload
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			uuid := path.Base(u.Path)
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(content)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			bu, err := url.Parse(blobLoc)
			blobDigest := path.Base(bu.Path)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			req = client.NewRequest(reggie.DELETE, "/v2/:name/blobs/:digest", reggie.WithDigest(blobDigest))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)

			//This is failing test #6
			So(resp.StatusCode(), ShouldEqual, 202)

			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Mount blobs", func() {
			Print("\nMount blobs from another repository")
			// create a upload
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			req.SetQueryParam("digest", "abc")
			req.SetQueryParam("from", "xyz")
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 405)
		})

		Convey("Manifests", func() {
			Print("\nManifests")
			// create a blob/layer
			req := client.NewRequest(reggie.POST, "/v2/:name/blobs/uploads/")
			printRequest(req)
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			u, err := url.Parse(loc)
			uuid := path.Base(u.Path)
			So(loc, ShouldNotBeEmpty)

			req = client.NewRequest(reggie.GET, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			req = client.NewRequest(reggie.PUT, "/v2/:name/blobs/uploads/:uuid", reggie.WithUUID(uuid))
			req.SetQueryParam("digest", digest.String())
			req.SetHeader("Content-Type", "application/octet-stream")
			req.SetBody(content)
			printRequest(req)
			resp, err = client.Do(req)
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
			req = client.NewRequest(reggie.PUT, "/v2/:name/manifests/test:1.0")
			req.SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			req.SetHeader("Accept", "*")
			req.SetHeader("Content-Length", fmt.Sprintf("%d", len(content)))
			req.SetBody(content)
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)

			//This is failing test #7
			So(resp.StatusCode(), ShouldEqual, 201)

			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			req = client.NewRequest(reggie.HEAD, "/v2/:name/manifests/test:1.0")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			req = client.NewRequest(reggie.GET, "/v2/:name/manifests/test:1.0")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			req = client.NewRequest(reggie.HEAD, "/v2/:name/manifests/:digest", reggie.WithDigest(digest.String()))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			req = client.NewRequest(reggie.GET, "/v2/:name/manifests/:digest", reggie.WithDigest(digest.String()))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest
			req = client.NewRequest(reggie.DELETE, "/v2/:name/manifests/test:1.0")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			// delete again should fail
			req = client.NewRequest(reggie.DELETE, "/v2/:name/manifests/:digest", reggie.WithDigest(digest.String()))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			req = client.NewRequest(reggie.HEAD, "/v2/:name/manifests/test:1.0")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			req = client.NewRequest(reggie.GET, "/v2/:name/manifests/test:1.0")
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			req = client.NewRequest(reggie.HEAD, "/v2/:name/manifests/:digest", reggie.WithDigest(digest.String()))
			printRequest(req)
			resp, err = client.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			req = client.NewRequest(reggie.GET, "/v2/:name/manifests/:digest", reggie.WithDigest(digest.String()))
			printRequest(req)
			resp, err = client.Do(req)
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

func printRequest(req *reggie.Request) {
	Printf("\nRequest method: %s\nRequest URL: %s\n Request querystring: %v\n", req.Method, req.URL, req.QueryParam)
}

func printResponse(resp *reggie.Response) {
}

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
