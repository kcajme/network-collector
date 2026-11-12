package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/internal/reporting"
	"github.com/gwoodwa1/network-collector/pkg/credentials"
	"golang.org/x/term"
)

func main() {
	// CLI flags
	var jsonOut bool
	var showVersion bool
	var cliFailOnFail bool
	var cliCredsInput bool
	var cliRSAToken bool
	var prettyOut bool
	var progressOut bool
	var approveAll bool
	var checkMode bool
	var planMode bool
	var lintMode bool
	var schemaMode bool
	var resumeDir string
	var configFile string
	var cliInventoryFile string
	var cliParsersFile string
	var limitExpression string
	var excludeExpression string
	var rerunFailedFile string
	var eventsFile string
	var cliSecurityMode string
	flag.StringVar(&configFile, "config", "config.yaml", "path to config file")
	flag.StringVar(&cliInventoryFile, "inventory", "", "path to inventory file")
	flag.StringVar(&cliParsersFile, "parsers", "", "path to parser module file")
	flag.StringVar(&limitExpression, "limit", "", "inventory selector expression to include (for example: site=london and role=core)")
	flag.StringVar(&excludeExpression, "exclude", "", "inventory selector expression to exclude")
	flag.StringVar(&rerunFailedFile, "rerun-failed", "", "run only devices marked failed in a previous results.json")
	flag.StringVar(&eventsFile, "events-jsonl", "", "append lifecycle events as JSON Lines to this file")
	flag.StringVar(&cliSecurityMode, "security-mode", "", "security policy override: production (default) or permissive")
	flag.BoolVar(&jsonOut, "json", false, "emit machine-readable JSON only")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&cliFailOnFail, "fail-on-fail", false, "exit non-zero if any validation fails or errors")
	flag.BoolVar(&cliCredsInput, "creds_input", false, "force interactive credentials (terminal runs prompt automatically when environment credentials are missing)")
	flag.BoolVar(&cliRSAToken, "rsa-token", false, "use an interactive RSA passcode, reuse it for startup connections, and prompt again before reconnecting")
	flag.BoolVar(&progressOut, "progress", true, "show live ASCII host progress in a terminal")
	flag.BoolVar(&prettyOut, "pretty", false, "show a coloured human-readable run summary")
	flag.BoolVar(&approveAll, "approve-all", false, "approve all manual workflow gates non-interactively")
	flag.BoolVar(&checkMode, "check", false, "preview changes without applying them")
	flag.BoolVar(&checkMode, "dry-run", false, "alias for --check")
	flag.BoolVar(&planMode, "plan", false, "resolve configuration offline and print a conditional device/step execution graph without connecting")
	flag.BoolVar(&lintMode, "lint", false, "validate configuration, imports, inventory, selectors, and variable flow without connecting")
	flag.BoolVar(&schemaMode, "schema", false, "print the JSON Schema for network-collector configuration and exit")
	flag.StringVar(&resumeDir, "resume", "", "resume a prior run directory after verifying its immutable manifest")
	flag.Parse()
	if jsonOut {
		prettyOut = false
	}
	if showVersion {
		fmt.Printf("network-collector %s\n", version)
		return
	}
	if schemaMode {
		if planMode || lintMode {
			slog.Error("--schema cannot be combined with --plan or --lint")
			os.Exit(1)
		}
		encoded, err := json.MarshalIndent(networkCollectorSchema(), "", "  ")
		if err != nil {
			slog.Error("error generating JSON Schema", "error", err)
			os.Exit(1)
		}
		fmt.Println(string(encoded))
		return
	}
	if planMode && lintMode {
		slog.Error("--plan and --lint cannot be combined; --plan includes lint validation")
		os.Exit(1)
	}
	if strings.TrimSpace(resumeDir) != "" && (planMode || lintMode || schemaMode || checkMode) {
		slog.Error("--resume cannot be combined with offline modes or --check")
		os.Exit(1)
	}

	config, failOnFail, err := loadConfig(configFile)
	if err != nil {
		slog.Error("error reading config", "config_file", configFile, "error", err)
		os.Exit(1)
	}
	config.checkMode = checkMode
	if strings.TrimSpace(cliSecurityMode) != "" {
		config.SecurityMode = cliSecurityMode
	}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on-fail" {
			failOnFail = cliFailOnFail
		}
	})

	if strings.TrimSpace(cliInventoryFile) != "" {
		config.InventoryFile = cliInventoryFile
	}
	if strings.TrimSpace(cliParsersFile) != "" {
		config.ParsersFile = cliParsersFile
	}
	if strings.TrimSpace(eventsFile) != "" {
		config.Output.EventsFile = eventsFile
	}
	reportLogoFolder := strings.TrimSpace(config.Report.LogoFolder)
	if reportLogoFolder != "" && !filepath.IsAbs(reportLogoFolder) {
		reportLogoFolder = filepath.Join(config.baseDir, reportLogoFolder)
	}
	if config.Report.Enabled {
		format := strings.ToLower(strings.TrimSpace(config.Report.Format))
		if format != "" && format != "html" {
			slog.Error("invalid report configuration", "error", "report.format currently supports only html")
			os.Exit(1)
		}
		if strings.TrimSpace(config.Output.SummaryFile) == "" {
			config.Output.SummaryFile = "results.json"
		}
		if strings.TrimSpace(config.Output.EventsFile) == "" {
			config.Output.EventsFile = "events.jsonl"
		}
		if reportErr := reporting.ValidateBranding(reporting.Config{
			LogoFolder: reportLogoFolder, HeaderLogo: config.Report.HeaderLogo, FooterLogo: config.Report.FooterLogo,
		}); reportErr != nil {
			slog.Error("invalid report branding", "error", reportErr)
			os.Exit(1)
		}
		if reportErr := reporting.ValidateTemplate(reporting.Config{
			Template: config.Report.Template,
		}); reportErr != nil {
			slog.Error("invalid report template", "error", reportErr)
			os.Exit(1)
		}
	}

	inventory, err := loadOptionalInventory(config.InventoryFile, configFile)
	if err != nil {
		slog.Error("error reading inventory", "inventory_file", config.InventoryFile, "error", err)
		os.Exit(1)
	}

	sshDevices, err := resolveInventoryDevices(config.SSH, inventory)
	if err != nil {
		slog.Error("error resolving SSH inventory", "error", err)
		os.Exit(1)
	}
	netconfDevices, err := resolveInventoryDevices(config.NETCONF, inventory)
	if err != nil {
		slog.Error("error resolving NETCONF inventory", "error", err)
		os.Exit(1)
	}
	devices := append([]DeviceConfig(nil), sshDevices...)
	devices = append(devices, netconfDevices...)
	for index := range devices {
		devices[index] = withPlaybookTimeout(devices[index], config)
	}
	securityMode, err := validateSecurityPolicy(config, devices)
	if err != nil {
		slog.Error("security policy rejected configuration", "error", err)
		os.Exit(1)
	}
	if securityMode == securityModePermissive {
		slog.Warn("permissive security mode is enabled; legacy algorithms or unverified transports may be allowed")
	} else {
		slog.Info("production security mode is enabled")
	}
	includeSelector, err := parseDeviceSelector(limitExpression)
	if err != nil {
		slog.Error("invalid --limit selector", "error", err)
		os.Exit(1)
	}
	excludeSelector, err := parseDeviceSelector(excludeExpression)
	if err != nil {
		slog.Error("invalid --exclude selector", "error", err)
		os.Exit(1)
	}
	var replayDevices map[string]bool
	if strings.TrimSpace(rerunFailedFile) != "" {
		replayDevices, err = loadFailedDevices(rerunFailedFile)
		if err != nil {
			slog.Error("error reading failed-device replay summary", "path", rerunFailedFile, "error", err)
			os.Exit(1)
		}
	}
	devices = filterDevices(devices, includeSelector, excludeSelector, replayDevices)
	if (includeSelector != nil || excludeSelector != nil || replayDevices != nil) && len(devices) == 0 {
		slog.Warn("inventory selection matched no devices")
	}
	rsaToken := cliRSAToken || config.Credentials.RSAToken
	rsaReuseMax, err := validateRSATokenReuse(config.Credentials, rsaToken, len(devices))
	if err != nil {
		slog.Error("RSA passcode reuse policy rejected configuration", "error", err)
		os.Exit(1)
	}
	if rsaToken {
		slog.Info("RSA passcode startup reuse is enabled", "selected_devices", len(devices), "maximum_devices", rsaReuseMax)
	}

	initialVariables, err := configVariables(config.Vars)
	if err != nil {
		slog.Error("invalid playbook variables", "error", err)
		os.Exit(1)
	}
	variableStates := make(map[string]*deviceVariableState)
	for index, device := range devices {
		key := variableScopeKey(device.Hostname, device.IP)
		state, exists := variableStates[key]
		if !exists {
			deviceVariables, variableErr := mergeInventoryVariables(initialVariables, device.InventoryVars)
			if variableErr != nil {
				slog.Error("invalid inventory variables", "hostname", device.Hostname, "error", variableErr)
				os.Exit(1)
			}
			state = &deviceVariableState{variables: deviceVariables}
			state.cond = sync.NewCond(&state.mu)
			variableStates[key] = state
		}
		state.order = append(state.order, index)
		if variableErr := preflightDeviceVariables(device, config.Workflows, state.variables); variableErr != nil {
			slog.Error("variable preflight failed", "hostname", device.Hostname, "error", variableErr)
			os.Exit(1)
		}
	}
	if planMode || lintMode {
		// Keep offline modes genuinely offline: all configuration, imports,
		// inventory, selector and variable-flow validation above has completed,
		// but credential providers, transports, event sinks and output files are
		// deliberately not initialized.
		if _, err := loadOptionalParsers(config.ParsersFile, configFile); err != nil {
			slog.Error("error reading parser modules", "parsers_file", config.ParsersFile, "error", err)
			os.Exit(1)
		}
		if lintMode {
			if jsonOut {
				fmt.Println(`{"valid":true,"mode":"lint","connections_opened":0}`)
			} else {
				fmt.Printf("lint passed: %d selected device(s); no credentials, connections, event sinks, or artifacts were opened\n", len(devices))
			}
			return
		}
		plan := buildOfflinePlan(config, devices)
		if jsonOut {
			encoded, marshalErr := json.MarshalIndent(plan, "", "  ")
			if marshalErr != nil {
				slog.Error("error encoding offline plan", "error", marshalErr)
				os.Exit(1)
			}
			fmt.Println(string(encoded))
		} else {
			fmt.Print(renderOfflinePlan(plan))
		}
		return
	}
	// Validate a resume request before credential providers are initialized.
	// A changed scope or an uncertain mutation must never trigger a new secret
	// lookup or a device connection.
	resumeDir = strings.TrimSpace(resumeDir)
	var resumeManifest runManifest
	var resumeCompleted map[string]string
	if resumeDir != "" {
		resolved, resolveErr := filepath.Abs(resumeDir)
		if resolveErr != nil {
			slog.Error("error resolving resume directory", "error", resolveErr)
			os.Exit(1)
		}
		manifest, verifyErr := verifyResumeManifest(resolved, configFile, config, devices)
		if verifyErr != nil {
			slog.Error("resume refused", "error", verifyErr)
			os.Exit(1)
		}
		uncertain, journalErr := uncertainJournalEntries(resolved)
		if journalErr != nil {
			slog.Error("error reading resume journal", "error", journalErr)
			os.Exit(1)
		}
		for _, entry := range uncertain {
			if entry.Kind != "ensure" {
				slog.Error("resume refused: an imperative mutation intent is uncertain and requires an audited operator decision", "hostname", entry.Hostname, "step", entry.Step, "kind", entry.Kind)
				os.Exit(1)
			}
			slog.Warn("resuming uncertain declarative ensure step; it will reconcile read-only state before deciding whether to apply", "hostname", entry.Hostname, "step", entry.Step)
		}
		resumeCompleted, journalErr = completedJournalEntries(resolved)
		if journalErr != nil {
			slog.Error("error reading completed resume entries", "error", journalErr)
			os.Exit(1)
		}
		resumeDir, resumeManifest = resolved, manifest
	}
	// #nosec G115 -- terminal descriptor conversion.
	menuEnabled := progressOut && !jsonOut && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	runContext, requestStop, finishRun := newRunCancellation(os.Stdin, os.Stderr, menuEnabled)
	defer finishRun()
	deviceCredentials := make([]credentials.Credentials, len(devices))
	var rsaAuth *rsaTokenAuth
	if len(devices) > 0 {
		// #nosec G115 -- x/term requires the OS file descriptor as int.
		providerType := selectCredentialProvider(config.Credentials.Provider, cliCredsInput || rsaToken,
			term.IsTerminal(int(os.Stdin.Fd())), os.Getenv("NET_USER"), os.Getenv("NET_PASSWORD"))
		credentialFile := strings.TrimSpace(config.Credentials.File)
		if credentialFile != "" && !filepath.IsAbs(credentialFile) {
			credentialFile = filepath.Join(filepath.Dir(configFile), credentialFile)
		}
		hashicorpConfig := config.Credentials.Hashicorp
		cyberArkConfig := config.Credentials.CyberArk
		for _, configuredPath := range []*string{
			&hashicorpConfig.CAFile, &hashicorpConfig.CertFile, &hashicorpConfig.KeyFile,
			&cyberArkConfig.CAFile, &cyberArkConfig.CertFile, &cyberArkConfig.KeyFile,
		} {
			if value := strings.TrimSpace(*configuredPath); value != "" && !filepath.IsAbs(value) {
				*configuredPath = filepath.Join(filepath.Dir(configFile), value)
			}
		}
		provider, providerErr := credentials.NewProvider(credentials.ProviderConfig{
			Type: providerType, File: credentialFile,
			TimeoutSeconds: config.Credentials.TimeoutSeconds,
			Hashicorp:      hashicorpConfig, OnePassword: config.Credentials.OnePassword,
			CyberArk: cyberArkConfig,
		}, os.Stdin, os.Stderr)
		if providerErr != nil {
			slog.Error("error configuring credential provider", "error", providerErr)
			os.Exit(1)
		}
		if strings.EqualFold(providerType, "interactive") || strings.EqualFold(providerType, "prompt") {
			shared, resolveErr := provider.Resolve(runContext, credentials.Target{Hostname: "selected inventory"})
			if resolveErr != nil {
				slog.Error("error resolving credentials", "error", resolveErr)
				os.Exit(1)
			}
			for index := range deviceCredentials {
				deviceCredentials[index] = shared
			}
			if rsaToken {
				rsaAuth = newRSATokenAuth(shared.Username, os.Stdin, os.Stderr)
			}
		} else {
			for index, device := range devices {
				deviceCredentials[index], err = provider.Resolve(runContext, credentials.Target{Hostname: device.Hostname, IP: device.IP, Profile: device.CredentialProfile})
				if err != nil {
					slog.Error("error resolving credentials", "hostname", device.Hostname, "error", err)
					os.Exit(1)
				}
			}
		}
	}
	sshTargets := make([]DeviceConfig, 0, len(devices))
	for _, device := range devices {
		if !stepsNeedSSH(device.Steps, config.Workflows, map[string]bool{}) && !(len(device.Steps) == 0 && strings.TrimSpace(device.Command) != "") {
			continue
		}
		sshTargets = append(sshTargets, device)
		if err := validateSSHSecurity(effectiveSSHSecurity(config.SSHSecurity, device.SSHSecurity)); err != nil {
			slog.Error("invalid SSH security configuration", "hostname", device.Hostname, "error", err)
			os.Exit(1)
		}
	}
	logSSHSecuritySummary(config.SSHSecurity, sshTargets)

	parserConfig, err := loadOptionalParsers(config.ParsersFile, configFile)
	if err != nil {
		slog.Error("error reading parser modules", "parsers_file", config.ParsersFile, "error", err)
		os.Exit(1)
	}
	parsers := map[string]ParserModuleConfig{}
	if parserConfig != nil && parserConfig.Parsers != nil {
		parsers = parserConfig.Parsers
	}

	runStarted := time.Now()
	if err := pruneSessionLogs(config.Output.RetentionDays, runStarted); err != nil {
		slog.Error("error pruning expired session logs", "error", err)
		os.Exit(1)
	}
	runID := "run-" + runStarted.Format("20060102T150405.000000000")
	runDir := ""
	if resumeDir != "" {
		runDir = resumeDir
		runID = resumeManifest.RunID
		slog.Info("resuming verified run", "run_id", runID, "directory", runDir)
	} else if outputEnabled(config, devices) {
		runDir, err = prepareRunOutput(config.Output, runID)
		if err != nil {
			slog.Error("error preparing structured output", "error", err)
			os.Exit(1)
		}
		slog.Info("recording structured output", "run_id", runID, "directory", runDir)
	}
	var journal *runJournal
	if runDir != "" {
		if resumeDir == "" {
			if _, manifestErr := writeRunManifest(runDir, runID, configFile, config, devices); manifestErr != nil {
				slog.Error("error writing immutable run manifest", "error", manifestErr)
				os.Exit(1)
			}
		}
		if journal, err = newRunJournal(runDir); err != nil {
			slog.Error("error opening run journal", "error", err)
			os.Exit(1)
		}
	}
	events := &eventDispatcher{runID: runID}
	eventPath := ""
	if configured := strings.TrimSpace(config.Output.EventsFile); configured != "" {
		eventPath, err = resolveWriteWithin(runDir, configured)
		if err != nil {
			slog.Error("error resolving lifecycle event output", "path", configured, "error", err)
			os.Exit(1)
		}
		sink, sinkErr := newJSONLEventSink(eventPath)
		if sinkErr != nil {
			slog.Error("error opening lifecycle event output", "path", eventPath, "error", sinkErr)
			os.Exit(1)
		}
		events.sinks = append(events.sinks, sink)
		slog.Info("recording lifecycle events", "path", eventPath)
	}
	for index, sinkConfig := range config.Output.EventSinks {
		sink, sinkErr := newNetworkEventSink(sinkConfig, config.SecurityMode)
		if sinkErr != nil {
			slog.Error("error configuring lifecycle event sink", "index", index, "type", sinkConfig.Type, "error", sinkErr)
			os.Exit(1)
		}
		events.sinks = append(events.sinks, sink)
		slog.Info("configured lifecycle event sink", "type", strings.ToLower(strings.TrimSpace(sinkConfig.Type)))
	}
	events.emit(lifecycleEvent{Type: "run.started", Data: map[string]interface{}{"playbook": config.NamePlaybook, "device_count": len(devices)}})

	if err := validateExecutionConfig(config.Execution); err != nil {
		slog.Error("invalid execution configuration", "error", err)
		os.Exit(1)
	}
	if err := validateSerialDomains(devices, config.Execution.SerialBy); err != nil {
		slog.Error("invalid redundancy scheduling configuration", "error", err)
		os.Exit(1)
	}
	if err := validateScheduleConfig(config.Schedule); err != nil {
		slog.Error("invalid schedule configuration", "error", err)
		os.Exit(1)
	}
	var approvals *approvalInput
	var approvalWriter io.Writer
	// #nosec G115 -- os.File.Fd is an operating-system file descriptor and
	// x/term requires that descriptor as int.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		approvals, approvalWriter = newApprovalInput(os.Stdin), os.Stdout
	}

	// Credentials and configuration are resolved before starting the live display.
	// Machine JSON and redirected output retain their established format.
	// #nosec G115 -- x/term requires an OS descriptor as int.
	displayEnabled := progressOut && !jsonOut && term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("TERM") != "dumb"
	previousLogger := slog.Default()
	var operationLog *os.File
	operationLogPath := ""
	if menuEnabled {
		config.checkpoints = map[string]*hostCheckpoint{}
		for _, device := range devices {
			config.checkpoints[variableScopeKey(device.Hostname, device.IP)] = &hostCheckpoint{}
		}
	}
	if displayEnabled {
		var logErr error
		operationLog, operationLogPath, logErr = openSessionLog("operation", config.NamePlaybook, runStarted)
		if logErr != nil {
			slog.Error("cannot open operation log", "error", logErr)
			os.Exit(1)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(operationLog, nil)))
		config.Output.ConsoleOutput = false
		config.progress = newProgressDisplay(os.Stdout, devices)
		config.progress.requestStop = requestStop
		// #nosec G115 -- terminal descriptor conversion.
		if term.IsTerminal(int(os.Stdin.Fd())) {
			config.progress.input = os.Stdin
		}
		events.sinks = append(events.sinks, config.progress)
		if rsaAuth != nil {
			rsaAuth.progress = config.progress
		}
		if menuEnabled {
			signal.Ignore(os.Interrupt)
		}
		config.progress.start()
	}

	runner := func(occurrence, index int, device DeviceConfig) deviceRunResult {
		state := variableStates[variableScopeKey(device.Hostname, device.IP)]
		state.mu.Lock()
		for state.next < len(state.order) && state.order[state.next] != index {
			state.cond.Wait()
		}
		credential := deviceCredentials[index]
		result := runSSHDeviceContext(runContext, index, occurrence, device, config, credential.Username, credential.Password, rsaAuth, jsonOut || displayEnabled, prettyOut, approveAll, approvals, approvalWriter, parsers, state.variables, runDir, events, journal, resumeCompleted)
		state.next++
		state.cond.Broadcast()
		state.mu.Unlock()
		return result
	}
	deviceResults, schedulingStopped := runRecurringScheduleContext(runContext, devices, config.Execution, config.Schedule, runner, time.Sleep)
	if menuEnabled && runContext.Err() == nil {
		deviceResults = waitForSessionActions(runContext, config.progress, devices, config.checkpoints, deviceResults, config.Schedule.Count > 1,
			func(index int, device DeviceConfig, variables map[string]string) deviceRunResult {
				key := variableScopeKey(device.Hostname, device.IP)
				variableStates[key].variables = variables
				credential := deviceCredentials[index]
				if rsaAuth != nil {
					user, password, promptErr := rsaAuth.prompt()
					if promptErr != nil {
						slog.Error("retry passcode prompt failed", "hostname", device.Hostname, "error", promptErr)
						return deviceRunResult{index: index, hostname: device.Hostname, ip: device.IP, failed: true}
					}
					credential.Username = user
					credential.Password = password
				}
				events.emit(lifecycleEvent{Type: "device.retry.confirmed", Hostname: device.Hostname, IP: device.IP})
				return runSSHDeviceContext(runContext, index, 0, device, config, credential.Username, credential.Password, rsaAuth, true, prettyOut, approveAll, approvals, approvalWriter, parsers, variables, runDir, events, journal, nil)
			})
	}
	if menuEnabled && config.Schedule.Count <= 1 && len(deviceResults) == len(devices) {
		schedulingStopped = false
	}

	occurrences := config.Schedule.Count
	if occurrences == 0 {
		occurrences = 1
	}
	deviceResultCount := len(devices) * occurrences
	runFailed := schedulingStopped
	resultsByIndex := make(map[int]deviceRunResult, len(deviceResults))
	for _, result := range deviceResults {
		resultsByIndex[result.index] = result
		if result.failed {
			runFailed = true
		}
	}
	var aggregated []deviceValidation
	var artifacts []outputArtifact
	var outcomes []deviceOutcome
	for index := 0; index < deviceResultCount; index++ {
		if result, ok := resultsByIndex[index]; ok {
			aggregated = append(aggregated, result.aggregated...)
			artifacts = append(artifacts, result.artifacts...)
			outcomes = append(outcomes, deviceOutcome{Hostname: result.hostname, IP: result.ip, Failed: result.failed, Duration: result.duration})
		}
	}
	summaryPath := ""
	if runDir != "" {
		summaryPath, err = writeRunSummary(config.Output, runDir, runSummary{
			RunID: runID, Playbook: config.NamePlaybook, StartedAt: runStarted, CompletedAt: time.Now(),
			Failed: runFailed, Validations: aggregated, Artifacts: artifacts, Devices: outcomes,
		})
		if err != nil {
			runFailed = true
			slog.Error("error writing run summary", "error", err)
		} else if summaryPath != "" {
			slog.Info("wrote run summary", "path", summaryPath)
		}
	}
	failed := runFailed
	eventData := map[string]interface{}{"duration_ns": time.Since(runStarted).Nanoseconds(), "device_results": len(deviceResults)}
	if runContext.Err() != nil {
		eventData["interrupted"] = true
	}
	events.emit(lifecycleEvent{Type: "run.completed", Failed: &failed, Data: eventData})
	events.close()
	if displayEnabled {
		slog.SetDefault(previousLogger)
		_ = operationLog.Close()
		fmt.Printf("Operation log: %s\nPer-host logs: session_logs/\n", operationLogPath)
	}
	reportFailed := false
	if config.Report.Enabled {
		reportPath, reportErr := reporting.Generate(reporting.Config{
			RunDir: runDir, SummaryFile: summaryPath, EventsFile: eventPath,
			Output: config.Report.Output, Template: config.Report.Template, Title: config.Report.Title,
			ChangeReference: config.Report.ChangeReference, LogoFolder: reportLogoFolder,
			HeaderLogo: config.Report.HeaderLogo, FooterLogo: config.Report.FooterLogo,
		})
		if reportErr != nil {
			reportFailed = true
			slog.Error("error generating change report", "error", reportErr)
		} else {
			slog.Info("wrote change report", "path", reportPath)
		}
	}

	// Emit aggregated JSON if requested
	if jsonOut {
		out, _ := json.MarshalIndent(aggregated, "", "  ")
		fmt.Println(string(out))
	} else if prettyOut && !displayEnabled {
		fmt.Print(renderPrettyResults(deviceResults, runFailed, time.Since(runStarted), prettyColourEnabled(os.Stdout)))
	}

	if runContext.Err() != nil {
		finishRun()
		os.Exit(130)
	}

	// Exit non-zero if any validation failed or errored and flag set
	if reportFailed {
		os.Exit(1)
	}
	if failOnFail {
		if runFailed {
			os.Exit(2)
		}
		for _, dv := range aggregated {
			if !dv.Recovered && (dv.Result.Status == "fail" || dv.Result.Status == "error") {
				os.Exit(2)
			}
		}
	}
}
