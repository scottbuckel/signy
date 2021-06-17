package main

import (
	"crypto/tls"
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"time"

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

func (v *WebServiceCommand) run() error {

	port := os.Getenv("NOTARY_PORT")
	if port == "" {
		port = "4445"
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
	log.Fatal(srv.ListenAndServeTLS("notary-wrapper.crt", "notary-wrapper.key"))
	log.Fatal(srv.ListenAndServe())

	return nil
}

type SignyReturn struct {
	SignyValidation string `json:"SignyValidation"`
	FailureReason   string `json:"FailureReason"`
	RandomNumber    int    `json:"RandomNumber"`
	ImageName       string `json:"ImageName"`
}

func SignyHandler(w http.ResponseWriter, r *http.Request) {

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
		min := 1
		max := 100
		SignyReturn.RandomNumber = rand.Intn(max-min) + min

		if SignyReturn.RandomNumber%2 == 0 {
			SignyReturn.FailureReason = "Number was Even, Evens are failures"
			SignyReturn.SignyValidation = "failure"
		} else {
			SignyReturn.FailureReason = ""
			SignyReturn.SignyValidation = "success"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(SignyReturn)
	}

	return

}
