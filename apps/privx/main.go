//
// Copyright (c) 2020 SSH Communications Security Inc.
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/SSHcom/gcloudwebhook"
	"github.com/markkurossi/tabulate"
)

func main() {
	add := flag.Bool("a", false, "Add new PrivX instance details")
	list := flag.Bool("l", false, "List PrivX instances")
	name := flag.String("n", "", "PrivX instance name")
	info := flag.Bool("i", false, "Print instance information")
	flag.Parse()

	args := flag.Args()

	if *add {
		if len(args) != 2 {
			log.Fatalf("No config and user-mapping files specified")
		}
		err := addInstance(*name, args[0], args[1])
		if err != nil {
			log.Fatalf("Failed to add instance: %s", err)
		}
	}

	if *list {
		err := listInstances()
		if err != nil {
			log.Fatalf("Failed to list instances: %s", err)
		}
	}

	if *info {
		err := instanceInfo(*name)
		if err != nil {
			log.Fatalf("Failed to get instance info: %s", err)
		}
	}
}

func addInstance(name, configPath, userMappingsPath string) error {
	if len(name) == 0 {
		log.Fatalf("Instance name not specified")
	}
	configData, err := readFile(configPath)
	if err != nil {
		return err
	}
	userMappingsData, err := readFile(userMappingsPath)
	if err != nil {
		return err
	}

	return gcloudwebhook.AddPrivXInstance(name, configData, userMappingsData)
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ioutil.ReadAll(f)
}

func listInstances() error {
	instances, err := gcloudwebhook.GetPrivXInstances()
	if err != nil {
		return err
	}

	for _, inst := range instances {
		fmt.Printf("%s\t%s\n", inst.Name, inst.Config.API.Endpoint)
		for k, v := range inst.UserMappings {
			fmt.Printf(" %s\t=> %s\n", k, v)
		}
	}

	return nil
}

func instanceInfo(name string) error {
	instances, err := gcloudwebhook.GetPrivXInstance(name)
	if err != nil {
		return err
	}
	for _, instance := range instances {
		tab := tabulate.NewUnicode()
		tab.Header("Field").SetAlign(tabulate.MR)
		tab.Header("Value").SetAlign(tabulate.ML)

		err = tabulate.Reflect(tab, tabulate.OmitEmpty, nil, instance)
		if err != nil {
			return err
		}
		tab.Print(os.Stdout)
	}

	return nil
}
