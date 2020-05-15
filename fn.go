//
// Copyright (c) 2020 SSH Communications Security Inc.
//
// All rights reserved.
//

package gcloudwebhook

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"os"

	"cloud.google.com/go/firestore"
	"github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/go-libs/fn"
)

const (
	// Realm specifies the HTTP authentication realm.
	Realm = "Jira PrivX Webhook"
	// Tenant specifies the OAuth2 authentication tenant.
	Tenant = "Jira-PrivX-Webhook"
	// InstanceEnvVar specifies the environment variable that holds
	// the PrivX instance name.
	InstanceEnvVar = "PRIVX_INSTANCE"
)

var (
	mux        *http.ServeMux
	projectID  string
	store      *auth.ClientStore
	tenant     *auth.Tenant
	authPubkey ed25519.PublicKey
	ctx        context.Context
	fs         *firestore.Client
)

func init() {
	mux = http.NewServeMux()
	mux.HandleFunc("/jira", jira)

	id, err := fn.GetProjectID()
	if err != nil {
		log.Fatalf("fn.GetProjectID: %s", err)
	}
	projectID = id

	store, err = auth.NewClientStore()
	if err != nil {
		log.Fatalf("NewClientStore: %s\n", err)
	}
	tenants, err := store.TenantByName(Tenant)
	if err != nil {
		log.Fatalf("store.TenantByName: %s\n", err)
	}
	if len(tenants) == 0 {
		log.Fatalf("Tenant %s not found\n", Tenant)
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

	ctx = context.Background()
	fs, err = firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("firestoer.NewClient: %s", err)
	}

	instanceName, ok := os.LookupEnv(InstanceEnvVar)
	if !ok {
		log.Fatalf("PrivX instance name not set $%s", InstanceEnvVar)
	}
	_ = instanceName
}

// PrivXWebhook is the cloud function entry point for Jira-PrivX
// integration.
func PrivXWebhook(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}

func tokenVerifier(message, sig []byte) bool {
	return ed25519.Verify(authPubkey, message, sig)
}

// Errorf formats an HTTP error response.
func Errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), code)
}
