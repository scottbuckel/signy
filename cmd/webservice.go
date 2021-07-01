package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cnabio/signy/pkg/intoto"
	"github.com/cnabio/signy/pkg/tuf"
	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func webserviceCommands() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webservice",
		Short: "webservice commands",
		Long:  "Commands for working with webservice.",
	}

	cmd.AddCommand(startWebService())
	return cmd
}

func startWebService() *cobra.Command {
	service := WebServiceCommand{}
	cmd := &cobra.Command{
		Use:   "serve [target reference]",
		Short: "Run a webservice",
		Long:  "Run a webservice",
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.run()
		},
	}

	//need to set this to automatically check for env variables for viper.get
	viper.AutomaticEnv()
	/*
		cmd.Flags().StringVarP(&push.pushImage, "image", "i", "", "container image to push (must be built on your local system)")
		cmd.Flags().StringVarP(&push.layout, "layout", "", "intoto/root.layout", "Path to the in-toto root layout file")
		cmd.Flags().StringVarP(&push.linkDir, "links", "", "intoto/", "Path to the in-toto links directory")
		cmd.Flags().StringVarP(&push.layoutKey, "layout-key", "", "intoto/root.pub", "Path to the in-toto root layout public keys")
		cmd.Flags().StringVarP(&push.registryUser, "registryUser", "", viper.GetString("PUSH_REGISTRY_USER"), "docker registry user, also uses the PUSH_REGISTRY_USER environment variable")
		cmd.Flags().StringVarP(&push.registryCredentials, "registryCredentials", "", viper.GetString("PUSH_REGISTRY_CREDENTIALS"), "docker registry credentials (api key or password), uses the PUSH_REGISTRY_CREDENTIALS environment variable")
	*/
	return cmd
}

type WebServiceCommand struct {
	WebServiceCommand string
}

var (
	notaryCertPath string
	notaryRootCa   string
	notaryCliPath  string
)

func (v *WebServiceCommand) run() error {

	port := os.Getenv("NOTARY_PORT")
	if port == "" {
		port = "4445"
	}

	notaryCertPath = os.Getenv("NOTARY_CERT_PATH")
	if notaryCertPath == "" {
		notaryCertPath = "/etc/certs/notary"
	}

	notaryRootCa = os.Getenv("NOTARY_ROOT_CA")
	if notaryRootCa == "" {
		notaryRootCa = "notary-server-svc"
	}

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// routes
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/signy", SignyHandler).Methods("GET")

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Infof("Starting webservice on %v/signy", port)

	log.Fatal(srv.ListenAndServeTLS(notaryCertPath+"/notary-wrapper.crt", notaryCertPath+"/notary-wrapper.key"))
	log.Fatal(srv.ListenAndServe())

	return nil
}

type SignyReturn struct {
	SignyValidation string `json:"SignyValidation"`
	FailureReason   string `json:"FailureReason"`
	ImageName       string `json:"ImageName"`
}

func SignyHandler(w http.ResponseWriter, r *http.Request) {

	notary_server := os.Getenv("notary_server")
	if notary_server == "" {
		notary_server = "https://notary-server-svc.notary.svc:4443"
	}

	dt := time.Now()

	log.Infof("Incoming webservice call: %v", dt.String())

	var SignyReturn SignyReturn

	SignyReturn.FailureReason = ""
	SignyReturn.SignyValidation = "failure"

	keys, ok := r.URL.Query()["image"]

	if !ok || len(keys[0]) < 1 {
		SignyReturn.FailureReason = "No Image Supplied"
		SignyReturn.SignyValidation = "failure"

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(SignyReturn)
	} else {
		SignyReturn.ImageName = keys[0]

		ctx := context.Background()
		cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())

		if err != nil {
			//return fmt.Errorf("Couldn't initialize dockerClient")
		}

		//pull the image from the repository
		log.Infof("Pulling image %v from registry", SignyReturn.ImageName)

		reader, err := cli.ImagePull(ctx, SignyReturn.ImageName, types.ImagePullOptions{})
		if err != nil {
			SignyReturn.FailureReason = err.Error()
			SignyReturn.SignyValidation = "failure"

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(SignyReturn)
			return
		}
		/*
			Trick from https://github.com/moby/moby/issues/28646 to wait for EOF, since ImagePull is Asynchronous
			TODO: configurable timeout? https://gist.github.com/ngauthier/d6e6f80ce977bedca601
		*/
		buf := make([]byte, 32*1024)
		for {
			_, er := reader.Read(buf)
			if er != nil {
				if er != io.EOF {
					err = er
				}
				break
			}
		}
		defer reader.Close()

		//there has to be a better way do do this, we inspect the image we just pulled, that image has a few digests (for example, if an image was tagged multiple times)
		imageDigests, _, err := cli.ImageInspectWithRaw(ctx, SignyReturn.ImageName)
		if err != nil {
			SignyReturn.FailureReason = err.Error()
			SignyReturn.SignyValidation = "failure"

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(SignyReturn)
			return
		}

		pulledSHA := ""
		for _, element := range imageDigests.RepoDigests {

			//remove the tag, since we have only digest now (image@sha256:)
			parts := strings.Split(SignyReturn.ImageName, ":")

			if strings.Contains(element, parts[0]) {
				//remove the image:@sha256, return only the actual sha
				pulledSHA = strings.Split(element, ":")[1]
			}
		}

		//trustServer := "notary-server-svc:4443"
		//trustServer := "https://notaryserver:4443"
		target, trustedSHA, err := tuf.GetTargetAndSHA(SignyReturn.ImageName, notary_server, "/etc/certs/notary/notary-server-svc/root-ca.crt", "/home/rootless/.signy/", "5s")
		if err != nil {
			SignyReturn.FailureReason = err.Error()
			SignyReturn.SignyValidation = "failure"

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(SignyReturn)
			return
		}

		if pulledSHA == trustedSHA {
			log.Infof("Pulled SHA matches TUF SHA: SHA256: %v matches %v", pulledSHA, trustedSHA)
		} else {

			SignyReturn.FailureReason = "Pulled image digest doesn't match TUF SHA! Pulled SHA: " + pulledSHA + " doesn't match TUF SHA: " + trustedSHA
			SignyReturn.SignyValidation = "failure"

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(SignyReturn)
			return
		}

		if target.Custom == nil {

			SignyReturn.FailureReason = "Error: TUF server doesn't have the custom field filled with in-toto metadata"
			SignyReturn.SignyValidation = "failure"

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(SignyReturn)
			return

		}

		err = intoto.VerifyOnOS(target, []byte(SignyReturn.ImageName))
		if err != nil {
			log.Infof("Error was:", err)
			SignyReturn.FailureReason = err.Error()
			SignyReturn.SignyValidation = "failure"

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(SignyReturn)
			return
		}

		SignyReturn.ImageName = pulledSHA
		SignyReturn.FailureReason = ""
		SignyReturn.SignyValidation = "success"

		/*
			//pull the data from notary
			target, trustedSHA, err := tuf.GetTargetAndSHA(SignyReturn.ImageName, trustServer, tlscacert, trustDir, timeout)
			if err != nil {
				log.Infof("Error: %v", err)
			}

			if pulledSHA == trustedSHA {
				log.Infof("Pulled SHA matches TUF SHA: SHA256: %v matches %v", pulledSHA, trustedSHA)
			} else {
				//return fmt.Errorf("Pulled image digest doesn't match TUF SHA! Pulled SHA: %v doesn't match TUF SHA: %v ", pulledSHA, trustedSHA)
			}

			if target.Custom == nil {
				//return fmt.Errorf("Error: TUF server doesn't have the custom field filled with in-toto metadata")
			}

			/*
				TODO: Allow other verifications like `Signy verify` does, also fail better when RuleVerificationError happen
					//return intoto.VerifyInContainer(target, []byte(v.pullImage), v.verificationImage, logLevel)
		*/
		//return intoto.VerifyOnOS(target, []byte(v.pullImage))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(SignyReturn)
	}

	return

}
