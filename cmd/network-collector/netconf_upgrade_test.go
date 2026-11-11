package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
)

func TestNETCONFIntegerCaptureIsBoundedAndPayloadOnly(t *testing.T) {
	capture := integerCaptureStep()
	capture.Command = ""
	capture.NETCONF = &NETCONFStepConfig{Operation: "rpc", Payload: `<install-add/>`}
	capture.RegisterInteger.Pattern = `<op-id>([0-9]+)</op-id>`
	activate := StepConfig{NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: `<activate><id>{{install_id}}</id></activate>`}}
	if err := preflightDeviceVariables(DeviceConfig{Steps: []StepConfig{capture, activate}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []NETCONFStepConfig{{Operation: "{{install_id}}"}, {Operation: "rpc", PayloadFile: "{{install_id}}"}, {Operation: "rpc", Target: "{{install_id}}"}} {
		if err := preflightDeviceVariables(DeviceConfig{Steps: []StepConfig{capture, {NETCONF: &bad}}}, nil, nil); err == nil {
			t.Fatal("integer crossed a forbidden NETCONF boundary")
		}
	}
	got, err := captureRegisteredInteger(capture, `<op-id>42</op-id>`)
	if err != nil || got != "42" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := captureRegisteredInteger(capture, `<op-id>42</op-id><op-id>43</op-id>`); err == nil {
		t.Fatal("ambiguous operation ID accepted")
	}
}

func TestXMLSnapshotsPreserveAssociationsAndIgnorePrefixAndOrder(t *testing.T) {
	root := "{urn:example}interfaces"
	a := `<rpc-reply message-id="1"><data><interfaces xmlns="urn:example"><interface><name>eth0</name><state>up</state></interface><interface><name>eth1</name><state>down</state></interface></interfaces></data></rpc-reply>`
	b := `<rpc-reply message-id="9"><data><x:interfaces xmlns:x="urn:example"><x:interface><x:state>down</x:state><x:name>eth1</x:name></x:interface><x:interface><x:state>up</x:state><x:name>eth0</x:name></x:interface></x:interfaces></data></rpc-reply>`
	first, err := parseXMLSnapshot(a, root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseXMLSnapshot(b, root)
	if err != nil || first != second {
		t.Fatalf("equivalent snapshots differ: %v", err)
	}
	changed := strings.ReplaceAll(a, "<name>eth0</name>", "<name>eth2</name>")
	third, _ := parseXMLSnapshot(changed, root)
	if first == third {
		t.Fatal("lost interface association")
	}
	for _, bad := range []string{`<data/>`, `<data>`, `text<interfaces xmlns="urn:example"/>`, `<!DOCTYPE x><interfaces xmlns="urn:example"/>`, `<interfaces xmlns="urn:wrong"/>`, `<interfaces xmlns="urn:example"/><interfaces xmlns="urn:example"/>`} {
		if _, err := parseXMLSnapshot(bad, root); err == nil {
			t.Fatalf("accepted invalid/missing snapshot: %s", bad)
		}
	}
}

func TestNETCONFReconnectResetsFailedSessionWithoutCLI(t *testing.T) {
	ctx, _ := interactionContext(t, nil)
	executor := newLazyNETCONFExecutor("192.0.2.1", "testuser", "testpass", netconfConnectionPolicy{})
	attempts := 0
	executor.connectClient = func(_, _, _ string, _ netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("router starting")
		}
		return &netconf.ScrapligoNETCONF{}, nil
	}
	ctx.netconf = executor
	// Exercise reset and readiness using short test intervals rather than real seconds.
	err := reconnectNETCONF(ctx, NETCONFStepConfig{Operation: "reconnect", MaxAttempts: 2, IntervalSeconds: 1})
	if err != nil || attempts != 2 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
	if err := validateNETCONFStep(NETCONFStepConfig{Operation: "reconnect", MaxAttempts: 40, IntervalSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	if err := validateNETCONFStep(NETCONFStepConfig{Operation: "reconnect"}); err == nil {
		t.Fatal("unbounded readiness accepted")
	}
}

func TestFailedNETCONFRPCDoesNotRunFollowingMutation(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{})
	executor := &fakeNETCONFStepExecutor{err: errors.New("connection lost before RPC acknowledgement")}
	ctx.netconf = executor
	stopped := executeSteps(ctx, nil, []StepConfig{{NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: "<reboot/>"}}, {NETCONF: &NETCONFStepConfig{Operation: "commit"}}})
	if !stopped || !*failed || len(executor.configs) != 1 {
		t.Fatalf("failed RPC continued: stopped=%v failed=%v calls=%d", stopped, *failed, len(executor.configs))
	}
}

func TestNETCONFUpgradeCapturesAndUsesOperationIDWithoutCLI(t *testing.T) {
	capture := integerCaptureStep()
	capture.Command = ""
	capture.NETCONF = &NETCONFStepConfig{Operation: "rpc", Payload: `<install-add xmlns="urn:test"/>`}
	capture.RegisterInteger.Pattern = `<op-id>([0-9]+)</op-id>`
	ctx, failed := interactionContext(t, map[string]string{})
	executor := &sequenceNETCONFExecutor{outputs: []string{`<op-id>42</op-id>`, `<state>success</state>`, `<ok/>`}}
	ctx.netconf = executor
	steps := []StepConfig{capture, {NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: `<get/>`}, Validation: &ValidationConfig{Extractor: "regex", Pattern: `<state>(success)</state>`, Condition: "eq", Expected: "success", ExpectedType: "string"}}, {NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: `<install-activate xmlns="urn:test"><id>{{install_id}}</id></install-activate>`}}}
	if err := preflightDeviceVariables(DeviceConfig{Steps: steps}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if executeSteps(ctx, nil, steps) || *failed {
		t.Fatal("NETCONF workflow failed")
	}
	if len(executor.configs) != 3 || !strings.Contains(executor.configs[2].Payload, "<id>42</id>") {
		t.Fatalf("wrong activation: %+v", executor.configs)
	}
}

func TestNETCONFConnectionAndOperationTimeoutsAreSeparate(t *testing.T) {
	policy := effectiveNETCONFPolicy(SSHSecurityConfig{}, DeviceConfig{Timeout: 5, OperationTimeout: 1800})
	if policy.connectionTimeout != 5*time.Second || policy.timeout != 1800*time.Second {
		t.Fatalf("timeouts mixed: %+v", policy)
	}
}
