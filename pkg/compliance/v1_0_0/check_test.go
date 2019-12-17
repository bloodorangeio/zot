//nolint (dupl)
package v1_0_0_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance"
	"github.com/anuvu/zot/pkg/compliance/v1_0_0"
	"github.com/phayes/freeport"
	"gopkg.in/resty.v1"
)

var (
	listenHost = "127.0.0.1"
	namespace  = "repo"
)

func TestWorkflows(t *testing.T) {
	ctrl, randomPort := startServer()
	defer stopServer(ctrl)
	v1_0_0.CheckWorkflows(t, &compliance.Config{
		Address:   fmt.Sprintf("http://%s:%s", listenHost, randomPort),
		Namespace: namespace,
	})
}

//func TestWorkflowsOutputJSON(t *testing.T) {
//	ctrl, randomPort := startServer()
//	defer stopServer(ctrl)
//	v1_0_0.CheckWorkflows(t, &compliance.Config{
//		Address:    listenHost,
//		Port:       randomPort,
//		OutputJSON: true,
//    Namespace: namespace,
//	})
//}

// start local server on random open port
func startServer() (*api.Controller, string) {
	portInt, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	randomPort := fmt.Sprintf("%d", portInt)
	fmt.Println(randomPort)

	config := api.NewConfig()
	config.HTTP.Address = listenHost
	config.HTTP.Port = randomPort
	ctrl := api.NewController(config)
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	//defer os.RemoveAll(dir)
	ctrl.Config.Storage.RootDirectory = dir
	go func() {
		// this blocks
		if err := ctrl.Run(); err != nil {
			return
		}
	}()

	baseURL := fmt.Sprintf("http://%s:%s", listenHost, randomPort)
	for {
		// poll until ready
		resp, _ := resty.R().Get(baseURL)
		if resp.StatusCode() == 404 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return ctrl, randomPort
}

func stopServer(ctrl *api.Controller) {
	ctrl.Server.Shutdown(context.Background())
}
