//
// Copyright (c) 2020 SSH Communications Security Inc.
//
// All rights reserved.
//

package gcloudwebhook

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"

	"github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/go-libs/fn"
)

const (
	REALM  = "Jira PrivX Webhook"
	TENANT = "Jira-PrivX-Webhook"
)

var (
	mux        *http.ServeMux
	projectID  string
	store      *auth.ClientStore
	tenant     *auth.Tenant
	authPubkey ed25519.PublicKey
)

func init() {
	mux = http.NewServeMux()
	mux.HandleFunc("/jira", Jira)

	id, err := fn.GetProjectID()
	if err != nil {
		log.Fatalf("fn.GetProjectID: %s", err)
	}
	projectID = id

	store, err = auth.NewClientStore()
	if err != nil {
		log.Fatalf("NewClientStore: %s\n", err)
	}
	tenants, err := store.TenantByName(TENANT)
	if err != nil {
		log.Fatalf("store.TenantByName: %s\n", err)
	}
	if len(tenants) == 0 {
		log.Fatalf("Tenant %s not found\n", TENANT)
	}
	tenant = tenants[0]

	assets, err := store.Asset(auth.ASSET_AUTH_PUBKEY)
	if err != nil {
		log.Fatalf("store.Asset(%s)\n", auth.ASSET_AUTH_PUBKEY)
	}
	if len(assets) == 0 {
		log.Fatalf("No auth public key\n")
	}
	authPubkey = ed25519.PublicKey(assets[0].Data)
}

func PrivXWebhook(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}

func tokenVerifier(message, sig []byte) bool {
	return ed25519.Verify(authPubkey, message, sig)
}

func Errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), code)
}
