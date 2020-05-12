//
// Copyright (c) 2020 SSH Communications Security Inc.
//
// All rights reserved.
//

package gcloudwebhook

import (
	"fmt"
	"log"
	"net/http"

	"github.com/markkurossi/go-libs/fn"
)

var (
	mux       *http.ServeMux
	projectID string
)

func init() {
	mux = http.NewServeMux()
	mux.HandleFunc("/jira", Jira)

	id, err := fn.GetProjectID()
	if err != nil {
		log.Fatalf("fn.GetProjectID: %s", err)
	}
	projectID = id
}

func PrivXWebhook(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}

func Errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), code)
}
