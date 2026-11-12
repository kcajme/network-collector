package main

import (
	"errors"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
)

type timeoutRecorder struct {
	timeout time.Duration
	seen    []time.Duration
	err     error
	outputs []string
}

func (r *timeoutRecorder) OperationTimeout() time.Duration     { return r.timeout }
func (r *timeoutRecorder) SetOperationTimeout(d time.Duration) { r.timeout = d }
func (r *timeoutRecorder) Execute(string) (string, error) {
	r.seen = append(r.seen, r.timeout)
	out := "ok"
	if len(r.outputs) > 0 {
		out = r.outputs[0]
		r.outputs = r.outputs[1:]
	}
	return out, r.err
}
func (r *timeoutRecorder) ExecuteNETCONF(NETCONFStepConfig) (string, error) { return r.Execute("") }
func (r *timeoutRecorder) ExecuteWithConfirmation(_, _, _ string, _ bool) (string, error) {
	return r.Execute("")
}

func TestStepOperationTimeoutRestoresAndInheritsNestedScopes(t *testing.T) {
	for _, protocol := range []string{"ssh", "netconf"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, failed := interactionContext(t, map[string]string{})
			recorder := &timeoutRecorder{timeout: 90 * time.Second}
			if protocol == "ssh" {
				ctx.sshCommand = recorder
			} else {
				ctx.netconf = recorder
			}
			command := func(seconds int) StepConfig {
				step := StepConfig{OperationTimeout: seconds}
				if protocol == "ssh" {
					step.Command = "show version"
				} else {
					step.NETCONF = &NETCONFStepConfig{Operation: "rpc", Payload: "<get/>"}
				}
				return step
			}
			steps := []StepConfig{command(1800), command(0), {OperationTimeout: 300, Block: &BlockConfig{Steps: []StepConfig{command(0), command(5), command(0)}}}, command(0)}
			if executeSteps(ctx, nil, steps) || *failed {
				t.Fatal("workflow failed")
			}
			want := []time.Duration{1800, 90, 300, 5, 300, 90}
			if len(recorder.seen) != len(want) {
				t.Fatalf("calls=%v", recorder.seen)
			}
			for i, seconds := range want {
				if recorder.seen[i] != seconds*time.Second {
					t.Fatalf("call %d: got %s want %s", i, recorder.seen[i], seconds*time.Second)
				}
			}
			if recorder.timeout != 90*time.Second {
				t.Fatal("timeout leaked after workflow")
			}
		})
	}
}

func TestStepOperationTimeoutAppliesToConfirmationAndRestoresAfterError(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{})
	recorder := &timeoutRecorder{timeout: 90 * time.Second, err: errors.New("prompt timeout")}
	ctx.sshCommand = recorder
	step := StepConfig{Command: "install activate", OperationTimeout: 1800, Confirmation: &ConfirmationConfig{Prompt: "continue", Response: "yes"}}
	if !executeSteps(ctx, nil, []StepConfig{step}) {
		t.Fatal("expected confirmation failure to stop")
	}
	if len(recorder.seen) != 1 || recorder.seen[0] != 1800*time.Second || recorder.timeout != 90*time.Second {
		t.Fatalf("bad scope: %+v", recorder)
	}
}

func TestStepOperationTimeoutAppliesToEveryRetryAttempt(t *testing.T) {
	ctx, failed := interactionContext(t, map[string]string{})
	recorder := &timeoutRecorder{timeout: 90 * time.Second, outputs: []string{"pending", "ready"}}
	ctx.sshCommand = recorder
	step := StepConfig{Command: "show status", OperationTimeout: 120, Retry: &RetryConfig{UntilPass: true, MaxAttempts: 2, IntervalSeconds: 1}, Validation: &ValidationConfig{Extractor: "regex", Pattern: "ready", Condition: "contains", Expected: "", ExpectedType: "string"}}
	executeSteps(ctx, nil, []StepConfig{step})
	if *failed || len(recorder.seen) != 2 || recorder.seen[0] != 120*time.Second || recorder.seen[1] != 120*time.Second || recorder.timeout != 90*time.Second {
		t.Fatalf("retry timeout scope: %+v", recorder)
	}
}

func TestStepOperationTimeoutCoversLazyAndReplacedConnections(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{})
	ctx.opts = []ssh.Option{ssh.WithOperationTimeout(45 * time.Second)}
	ctx.netconfPolicy = netconfConnectionPolicy{timeout: 30 * time.Second}
	lazy := newLazyNETCONFExecutor("192.0.2.1", "testuser", "testpass", ctx.netconfPolicy)
	lazy.connectClient = func(_, _, _ string, policy netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error) {
		if policy.timeout != 1800*time.Second {
			t.Fatalf("lazy connect timeout: %s", policy.timeout)
		}
		c := &netconf.ScrapligoNETCONF{}
		c.SetOperationTimeout(policy.timeout)
		return c, nil
	}
	ctx.netconf = lazy
	var client *ssh.Client
	restore := scopeOperationTimeout(ctx, &client, 1800*time.Second)
	if err := lazy.connect(); err != nil {
		t.Fatal(err)
	}
	client = ssh.NewClient(ctx.opts...)
	restore()
	if client.OperationTimeout() != 45*time.Second || lazy.client.OperationTimeout() != 30*time.Second || lazy.policy.timeout != 30*time.Second || ctx.netconfPolicy.timeout != 30*time.Second {
		t.Fatal("timeout leaked from newly established connections")
	}
}

func TestPlaybookTargetAndStepTimeoutValidation(t *testing.T) {
	config, _, err := loadConfig(securityConfigFile(t, "operation_timeout: 1800\nssh:\n  - operation_timeout: 120\n    steps:\n      - cmd: show version\n        operation_timeout: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if config.OperationTimeout != 1800 || config.SSH[0].OperationTimeout != 120 || config.SSH[0].Steps[0].OperationTimeout != 10 {
		t.Fatal("timeout decoding lost values")
	}
	if withPlaybookTimeout(DeviceConfig{}, config).OperationTimeout != 1800 || withPlaybookTimeout(config.SSH[0], config).OperationTimeout != 120 {
		t.Fatal("wrong default precedence")
	}
	invalid := []int{-1}
	if strconv.IntSize == 64 {
		overflow := int64(1) << 40
		invalid = append(invalid, int(overflow))
	}
	for _, value := range invalid {
		step := StepConfig{Command: "show version", OperationTimeout: value}
		if err := preflightDeviceVariables(DeviceConfig{Steps: []StepConfig{step}}, nil, nil); err == nil {
			t.Fatalf("invalid timeout accepted: %d", value)
		}
	}
}

func TestParallelStepOperationTimeoutsUseIndependentPolicies(t *testing.T) {
	ctx, _ := interactionContext(t, map[string]string{})
	ctx.netconfPolicy = netconfConnectionPolicy{timeout: 30 * time.Second}
	var mu sync.Mutex
	var seen []int
	ctx.netconfConnector = func(_, _, _ string, policy netconfConnectionPolicy) (*netconf.ScrapligoNETCONF, error) {
		mu.Lock()
		seen = append(seen, int(policy.timeout/time.Second))
		mu.Unlock()
		return nil, errors.New("stop after recording branch policy")
	}
	branches := []StepConfig{}
	for _, seconds := range []int{10, 20, 0} {
		branches = append(branches, StepConfig{OperationTimeout: seconds, NETCONF: &NETCONFStepConfig{Operation: "rpc", Payload: "<get/>"}})
	}
	executeSteps(ctx, nil, []StepConfig{{Parallel: &ParallelConfig{Steps: branches}}})
	sort.Ints(seen)
	if len(seen) != 3 || seen[0] != 10 || seen[1] != 20 || seen[2] != 30 || ctx.netconfPolicy.timeout != 30*time.Second {
		t.Fatalf("branch timeouts leaked: %v parent=%s", seen, ctx.netconfPolicy.timeout)
	}
}
