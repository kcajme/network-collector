package main

import (
	"path/filepath"
	"testing"
)

func TestRepositorySampleLoadsWithStrictSchema(t *testing.T) {
	config, _, err := loadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.NETCONF) != 2 {
		t.Fatalf("expected two sample NETCONF targets, got %d", len(config.NETCONF))
	}
	for _, target := range config.NETCONF {
		if len(target.Steps) != 1 || target.Steps[0].NETCONF == nil || target.Steps[0].NETCONF.Operation != "rpc" {
			t.Fatalf("invalid sample NETCONF target: %+v", target)
		}
	}
}
