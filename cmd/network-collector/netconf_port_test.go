package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNETCONFPortInventoryInheritanceAndOverride(t *testing.T) {
	for _, port := range []int{0, 22, 1830} {
		device := applyInventoryHost(DeviceConfig{NETCONFPort: port}, InventoryHostConfig{NETCONFPort: 22})
		want := port
		if want == 0 {
			want = 22
		}
		policy := effectiveNETCONFPolicy(SSHSecurityConfig{}, device)
		if policy.port != want {
			t.Fatalf("port=%d: policy=%+v", port, policy)
		}
		sequential := newLazyNETCONFExecutor("192.0.2.10", "collector", "secret", policy)
		assertNETCONFPolicy(t, captureNETCONFConnect(t, sequential), policy)
		parallel := newParallelNETCONFExecutor(&stepExecutionContext{ip: "192.0.2.10", username: "collector", password: "secret", netconfPolicy: policy})
		assertNETCONFPolicy(t, captureNETCONFConnect(t, parallel), policy)
	}
	if effectiveNETCONFPolicy(SSHSecurityConfig{}, DeviceConfig{}).port != 0 {
		t.Fatal("omitted port must use driver default")
	}
}

func TestNETCONFPortStrictYAMLAndInvalidValues(t *testing.T) {
	for _, port := range []int{0, 22, 830, -1, 65536} {
		config, _, err := loadConfig(securityConfigFile(t, fmt.Sprintf("netconf:\n  - type: cisco_iosxr\n    netconf_port: %d\n", port)))
		invalid := port < 0 || port > 65535
		if (err != nil) != invalid {
			t.Fatalf("config port %d: %v", port, err)
		}
		if !invalid && config.NETCONF[0].NETCONFPort != port {
			t.Fatal("port lost during decoding")
		}
		path := filepath.Join(t.TempDir(), "inventory.yaml")
		if err := os.WriteFile(path, []byte(fmt.Sprintf("hosts:\n  - name: router-01\n    ip: 192.0.2.1\n    netconf_port: %d\n", port)), 0600); err != nil {
			t.Fatal(err)
		}
		inventory, err := loadInventory(path, "")
		if (err != nil) != invalid {
			t.Fatalf("inventory port %d: %v", port, err)
		}
		if !invalid && inventory.Hosts[0].NETCONFPort != port {
			t.Fatal("inventory port lost during decoding")
		}
	}
}
