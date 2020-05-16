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
	"github.com/SSHcom/privx-sdk-go/api"
	"github.com/SSHcom/privx-sdk-go/api/rolestore"
	"github.com/SSHcom/privx-sdk-go/oauth"
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
	instance   *Instance
	roleStore  *rolestore.Client
	userIDs    = make(map[string]string)
	roleIDs    = make(map[string]string)
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
		_, ok = os.LookupEnv("GCP_PROJECT")
		if ok {
			log.Fatalf("PrivX instance name not set: $%s", InstanceEnvVar)
		} else {
			log.Printf("Privx instance name not set: $%s", InstanceEnvVar)
		}
	} else {
		instances, err := GetPrivXInstance(instanceName)
		if err != nil {
			log.Fatalf("GetPrivXInstances: %s", err)
		}
		if len(instances) != 1 {
			log.Fatalf("Invalid amount (%d) of PrivX instances with name '%s'",
				len(instances), instanceName)
		}
		instance = instances[0]
		initPrivX()
	}
}

func initPrivX() {
	auth, err := oauth.NewClient(instance.Config.Auth,
		instance.Config.API.Endpoint,
		instance.Config.API.Certificate.X509, true)
	if err != nil {
		log.Fatal(err)
	}
	client, err := api.NewClient(api.Authenticator(auth),
		api.Endpoint(instance.Config.API.Endpoint),
		api.X509(instance.Config.API.Certificate.X509))
	if err != nil {
		log.Fatal(err)
	}
	roleStore, err = rolestore.NewClient(client)
	if err != nil {
		log.Fatal(err)
	}

	// Resolve user IDs
	for k, v := range instance.UserMappings {
		users, err := roleStore.SearchUsers(v, "")
		if err != nil {
			log.Fatalf("Searching user '%s' failed: %s", v, err)
		}
		switch len(users) {
		case 0:
			log.Printf("User '%s' not found", v)

		case 1:
			userIDs[k] = users[0].ID

		default:
			log.Printf("Multiple matches (%d) for user '%s'", len(users), v)
		}
	}

	// Resolve role IDs.
	roles, err := roleStore.GetRoles()
	if err != nil {
		log.Fatalf("Failed to get roles: %s", err)
	}
	for _, role := range roles {
		roleIDs[role.Name] = role.ID
	}
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
