/*
Copyright 2020 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/homedir"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

type oidcService struct {
	ctx        context.Context
	provider   *oidc.Provider
	host       string
	clientid   string
	issuer     string
	verifier   *oidc.IDTokenVerifier
	config     oauth2.Config
	state      string
	httpServer *http.Server
}

func randSeq(n int) string {
	max := big.NewInt(int64(len(letters)))
	b := make([]rune, n)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = letters[n.Int64()]
	}
	return string(b)
}

func main() {
	host := flag.String("host", "", "openunison hostname (and port if needed)")

	ctx := flag.String("context", "", "an existing context in the kubectl configuration file")

	flag.Parse()

	pathOptions := clientcmd.NewDefaultPathOptions()
	curCfg, err := pathOptions.GetStartingConfig()

	if err != nil {
		panic(err)
	}

	if *host == "" && *ctx == "" {
		if curCfg.CurrentContext == "" {
			fmt.Println("No host or context set")
			os.Exit(1)
		} else {
			ctx = &curCfg.CurrentContext
		}
	}

	if *host == "" && *ctx != "" {
		hostName, err := findHostFromContext(*ctx, curCfg)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		host = &hostName
	}

	if checkCurrentConfig(*host, curCfg) {
		fmt.Println("Invalid context or does not exist, launching browser to login")
		runOidc(*host)
	} else {
		fmt.Println("kubectl is ready to use")
	}

}

func findHostFromContext(ctx string, curCfg *api.Config) (string, error) {

	cfgCtx := curCfg.Contexts[ctx]

	if cfgCtx == nil {
		return "", fmt.Errorf("context %s does not exist", ctx)
	}

	authData := curCfg.AuthInfos[cfgCtx.AuthInfo]

	if authData == nil {
		return "", fmt.Errorf("user %s does not exist", cfgCtx.AuthInfo)
	}

	if authData.AuthProvider != nil && authData.AuthProvider.Name == "oidc" {
		issuerURL := authData.AuthProvider.Config["idp-issuer-url"]
		parsedIssuerURL, err := url.Parse(issuerURL)
		if err != nil {
			return "", err
		}
		return parsedIssuerURL.Host, nil
	} else {
		return "", fmt.Errorf("user %s is not oidc", cfgCtx.AuthInfo)
	}

}

func checkCurrentConfig(host string, curCfg *api.Config) bool {

	// determine expected issuer
	openunisonIssuerUrl := "https://" + host + "/auth/idp/k8sIdp"

	fmt.Printf("Checking for existing issuer %s\n", openunisonIssuerUrl)

	for userName, authData := range curCfg.AuthInfos {
		if authData.AuthProvider != nil && authData.AuthProvider.Name == "oidc" {
			fmt.Printf("checking %s %s\n", userName, authData.AuthProvider.Config["idp-issuer-url"])
			if authData.AuthProvider.Config != nil && authData.AuthProvider.Config["idp-issuer-url"] == openunisonIssuerUrl {
				// found the user, need to find the context
				for contextName, ctx := range curCfg.Contexts {
					if ctx.AuthInfo == userName {
						fmt.Printf("Setting context %s\n", contextName)
						curCfg.CurrentContext = contextName

						// save the config
						clientConfig := clientcmd.NewDefaultClientConfig(*curCfg, nil)
						clientcmd.ModifyConfig(clientConfig.ConfigAccess(), *curCfg, false)

						// reload and attempt to get the version to force a reload
						var kubeconfig *string
						if home := homedir.HomeDir(); home != "" {
							kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
						} else {
							kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
						}
						flag.Parse()

						config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
						if err != nil {
							panic(err)
						}
						clientset, err := kubernetes.NewForConfig(config)
						if err != nil {
							panic(err)
						}

						fmt.Printf("Checking for valid token\n")
						_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), "default", metav1.GetOptions{})
						if err != nil {
							if nerr, ok := err.(*errors.StatusError); ok && nerr.ErrStatus.Code == 403 {
								return false
							} else {
								return true
							}
						} else {
							return false
						}

					}
				}
			}
		}

	}

	return true
}

func runOidc(host string) {
	fmt.Printf("Starting OpenID Connect for host %s\n", host)
	oidc := &oidcService{
		clientid: "cli-local",
		issuer:   "https://" + host + "/auth/idp/k8s-login-cli",
		host:     host,
	}

	browser.OpenURL("https://" + oidc.host + "/cli-login")

	m := http.NewServeMux()
	m.HandleFunc("/", oidc.oidcStartLogin)
	m.HandleFunc("/redirect", oidc.oidcHandleRedirect)

	oidc.httpServer = &http.Server{Addr: "127.0.0.1:8400", Handler: m}

	go func() {
		time.Sleep(30 * time.Second)
		fmt.Println("Timeout wating for login")
		os.Exit(1)

	}()

	oidc.httpServer.ListenAndServe()
	os.Exit(0)
}

func (oidcSvc *oidcService) oidcStartLogin(w http.ResponseWriter, r *http.Request) {
	var err error
	oidcSvc.ctx = context.Background()

	oidcSvc.provider, err = oidc.NewProvider(oidcSvc.ctx, oidcSvc.issuer)
	if err != nil {
		panic(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: oidcSvc.clientid,
	}

	oidcSvc.verifier = oidcSvc.provider.Verifier(oidcConfig)

	oidcSvc.config = oauth2.Config{
		ClientID:    oidcSvc.clientid,
		Endpoint:    oidcSvc.provider.Endpoint(),
		RedirectURL: "http://127.0.0.1:8400/redirect",
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcSvc.state = randSeq(24)

	http.Redirect(w, r, oidcSvc.config.AuthCodeURL(oidcSvc.state), http.StatusFound)

}

func (oidcSvc *oidcService) oidcHandleRedirect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != oidcSvc.state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := oidcSvc.config.Exchange(oidcSvc.ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	_, err = oidcSvc.verifier.Verify(oidcSvc.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	httpReq, err := http.NewRequest("GET", "https://"+oidcSvc.host+"/k8slogin/token/user", nil)

	if err != nil {
		panic(err)
	}

	httpReq.Header.Add("Authorization", rawIDToken)

	httpResp, err := http.DefaultClient.Do(httpReq)

	if err != nil {
		panic(err)
	}

	data, err := ioutil.ReadAll(httpResp.Body)

	if err != nil {
		panic(err)
	}

	var objmap map[string]json.RawMessage
	err = json.Unmarshal(data, &objmap)

	var tokenmap map[string]json.RawMessage
	err = json.Unmarshal(objmap["token"], &tokenmap)

	userName := byte2string(objmap["displayName"])
	k8sURL := byte2string(tokenmap["kubectl Windows Command"])
	ctxName := byte2string(tokenmap["kubectl Command"])
	refreshToken := byte2string(tokenmap["refresh_token"])
	userIDToken := byte2string(tokenmap["id_token"])

	var ouCert, k8sCert string

	data, ok = tokenmap["OpenUnison Server CA Certificate"]
	if ok {
		ouCert = base64.StdEncoding.EncodeToString([]byte(byte2string(data)))
	} else {
		ouCert = ""
	}

	data, ok = tokenmap["Kubernetes API Server CA Certificate"]
	if ok {
		k8sCert = byte2string(data)
	} else {
		k8sCert = ""
	}

	pathOptions := clientcmd.NewDefaultPathOptions()
	curCfg, err := pathOptions.GetStartingConfig()

	cluster, ok := curCfg.Clusters[ctxName]
	if !ok {
		cluster = api.NewCluster()
		curCfg.Clusters[ctxName] = cluster
	}

	cluster.Server = k8sURL
	cluster.InsecureSkipTLSVerify = false

	if len(k8sCert) == 0 {
		cluster.CertificateAuthorityData = nil
	} else {
		cluster.CertificateAuthorityData = []byte(k8sCert)
	}

	authInfo, ok := curCfg.AuthInfos[userName]

	if !ok {
		authInfo = api.NewAuthInfo()
		curCfg.AuthInfos[userName] = authInfo
	}

	authInfo.AuthProvider = &api.AuthProviderConfig{
		Name:   "oidc",
		Config: make(map[string]string),
	}

	authInfo.AuthProvider.Config["client-id"] = "kubernetes"
	authInfo.AuthProvider.Config["id-token"] = userIDToken
	authInfo.AuthProvider.Config["idp-certificate-authority-data"] = ouCert
	authInfo.AuthProvider.Config["idp-issuer-url"] = "https://" + oidcSvc.host + "/auth/idp/k8sIdp"
	authInfo.AuthProvider.Config["refresh-token"] = refreshToken

	context, ok := curCfg.Contexts[ctxName]

	if !ok {
		context = api.NewContext()
		curCfg.Contexts[ctxName] = context
	}

	context.AuthInfo = userName
	context.Cluster = ctxName

	curCfg.CurrentContext = ctxName

	clientConfig := clientcmd.NewDefaultClientConfig(*curCfg, nil)

	clientcmd.ModifyConfig(clientConfig.ConfigAccess(), *curCfg, false)

	http.Redirect(w, r, "https://"+oidcSvc.host+"/auth/forms/cli-login-finished.jsp", http.StatusFound)

	fmt.Println("kubectl configuration created")

	//time.Sleep(time.Second * 10)

	go oidcSvc.httpServer.Shutdown(oidcSvc.ctx)

}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func byte2string(data []byte) string {
	return (strings.Replace(strings.Replace(strings.Replace(string(data[1:len(data)-1]), "\\n", "\n", -1), "\\r", "", -1), "\\u003d", "=", -1))
}
