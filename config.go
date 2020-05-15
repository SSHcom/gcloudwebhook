//
// Copyright (c) 2020 SSH Communications Security Inc.
//
// All rights reserved.
//

package gcloudwebhook

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/SSHcom/privx-sdk-go/config"
	"google.golang.org/api/iterator"
)

const (
	collection = "PrivX"
)

// Instance contains configuration information for a PrivX instance.
type Instance struct {
	Name         string
	Config       *config.Config
	UserMappings map[string]string
}

// AddPrivXInstance adds the named PrivX instance to the PrivX
// collection in Firestore. TODO, must change to use correct types
// instead of []byte configs.
func AddPrivXInstance(name string, config, userMappings []byte) error {
	configB64 := base64.RawURLEncoding.EncodeToString(config)
	userMappingsB64 := base64.RawURLEncoding.EncodeToString(userMappings)

	_, _, err := fs.Collection(collection).Add(ctx,
		map[string]interface{}{
			"name":         name,
			"config":       configB64,
			"userMappings": userMappingsB64,
		})
	return err
}

// GetPrivXInstances returns all known PrivX instances.
func GetPrivXInstances() ([]*Instance, error) {
	iter := fs.Collection(collection).DocumentRefs(ctx)

	var result []*Instance

	for {
		ref, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		doc, err := ref.Get(ctx)
		if err != nil {
			return nil, err
		}
		instance, err := unmarshalInstance(doc.Data())
		if err != nil {
			return nil, err
		}
		result = append(result, instance)
	}

	return result, nil
}

func unmarshalInstance(data map[string]interface{}) (*Instance, error) {
	name, ok := data["name"].(string)
	if !ok {
		return nil, fmt.Errorf("No 'name'")
	}
	configB64, ok := data["config"].(string)
	if !ok {
		return nil, fmt.Errorf("No 'config'")
	}
	configData, err := base64.RawURLEncoding.DecodeString(configB64)
	if err != nil {
		return nil, err
	}

	userMappingsB64, ok := data["userMappings"].(string)
	if !ok {
		return nil, fmt.Errorf("No 'userMappings'")
	}
	userMappingsData, err := base64.RawURLEncoding.DecodeString(userMappingsB64)
	if err != nil {
		return nil, err
	}

	cfg := new(config.Config)
	err = toml.Unmarshal(configData, cfg)
	if err != nil {
		return nil, err
	}

	userMappings := make(map[string]string)
	err = json.Unmarshal(userMappingsData, &userMappings)
	if err != nil {
		return nil, err
	}

	return &Instance{
		Name:         name,
		Config:       cfg,
		UserMappings: userMappings,
	}, nil
}
