package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSimpleHostsInventoryExpandsSharedWorkflowInOrder(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(filepath.Join(dir, "inventory.yaml"), []byte("hosts:\n  - name: router-b\n    ip: 192.0.2.2\n  - name: router-a\n    ip: 192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := loadInventory("inventory.yaml", configPath)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := resolveInventoryDevices([]DeviceConfig{{Type: "cisco_iosxr", Steps: []StepConfig{{Name: "version", Command: "show version"}}}}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 || devices[0].Hostname != "router-b" || devices[1].Hostname != "router-a" || devices[0].IP != "192.0.2.2" || devices[1].Type != "cisco_iosxr" || len(devices[0].Steps) != 1 {
		t.Fatalf("bad shared targets: %+v", devices)
	}
}

func TestSimpleInventoryDoesNotBroadenExplicitTargets(t *testing.T) {
	inventory := &InventoryConfig{Hosts: []InventoryHostConfig{{Name: "one", IP: "1"}, {Name: "two", IP: "2"}}}
	for _, device := range []DeviceConfig{{Host: "one", Type: "cisco_iosxr"}, {Hostname: "inline", IP: "3", Type: "cisco_iosxr"}} {
		targets, err := resolveInventoryDevices([]DeviceConfig{device}, inventory)
		if err != nil || len(targets) != 1 {
			t.Fatalf("explicit target expanded unexpectedly: %+v %v", targets, err)
		}
	}
}

func TestSimpleSharedWorkflowRejectsEmptyInventoryAndMissingDriver(t *testing.T) {
	for _, inventory := range []*InventoryConfig{{}, {Hosts: []InventoryHostConfig{{Name: "one", IP: "1"}}}} {
		_, err := resolveInventoryDevices([]DeviceConfig{{Command: "show version"}}, inventory)
		if err == nil {
			t.Fatal("shared workflow accepted incomplete inventory")
		}
	}
}

func TestInventoryRequiresStandardHostsKey(t *testing.T) {
	for _, content := range []string{"host: []\n", "host: []\nhosts: []\n", "host:\n  - name: router-01\n    ip: 192.0.2.1\n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "inventory.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadInventory(path, "")
		if err == nil || !strings.Contains(err.Error(), "must use hosts:") {
			t.Fatalf("singular inventory host list not rejected clearly: %v", err)
		}
	}
}
