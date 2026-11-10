package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/internal/secureartifact"
)

const (
	runManifestFilename = "run-manifest.json"
	runJournalFilename  = "run-journal.jsonl"
)

// runManifest binds a resumable run to the exact resolved scope. Digests are
// stored as digests only; raw configuration values and command output never
// enter this file.
type runManifest struct {
	InputsDigest      string    `json:"inputs_digest"`
	ResumeUnsupported string    `json:"resume_unsupported,omitempty"`
	FormatVersion     int       `json:"format_version"`
	RunID             string    `json:"run_id"`
	CreatedAt         time.Time `json:"created_at"`
	ConfigDigest      string    `json:"config_digest"`
	InventoryDigest   string    `json:"inventory_digest,omitempty"`
	PlanDigest        string    `json:"plan_digest"`
}

// runJournalEntry is append-only write-ahead state. An intent without a later
// completed record is uncertain, which is the only safe interpretation after
// process loss or an interrupted transport.
type runJournalEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	State       string    `json:"state"`
	Hostname    string    `json:"hostname"`
	IP          string    `json:"ip"`
	ExecutionID string    `json:"execution_id,omitempty"`
	InputDigest string    `json:"input_digest,omitempty"`
	Step        string    `json:"step"`
	Occurrence  int       `json:"occurrence"`
	Kind        string    `json:"kind,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

type runJournal struct {
	mu   sync.Mutex
	path string
}

func newRunJournal(runDir string) (*runJournal, error) {
	if strings.TrimSpace(runDir) == "" {
		return nil, fmt.Errorf("resumable runs require an output directory")
	}
	path, err := resolveWriteWithin(runDir, runJournalFilename)
	if err != nil {
		return nil, err
	}
	return &runJournal{path: path}, nil
}

func (j *runJournal) append(entry runJournalEntry) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := secureartifact.EnsureDir(filepath.Dir(j.path)); err != nil {
		return err
	}
	file, err := secureartifact.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func fileDigest(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
	if err != nil {
		return "", err
	}
	if len(content) > 64*1024*1024 {
		return "", fmt.Errorf("input file exceeds 64 MiB")
	}
	return bytesDigest(content), nil
}

func writeRunManifest(runDir, runID, configFile string, config Config, devices []DeviceConfig) (runManifest, error) {
	configDigest, err := fileDigest(configFile)
	if err != nil {
		return runManifest{}, fmt.Errorf("digest config: %w", err)
	}
	inventoryPath := strings.TrimSpace(config.InventoryFile)
	if inventoryPath != "" {
		inventoryPath = resolveInventoryPath(inventoryPath, configFile)
	}
	inventoryDigest, err := fileDigest(inventoryPath)
	if err != nil {
		return runManifest{}, fmt.Errorf("digest inventory: %w", err)
	}
	plan := buildOfflinePlan(config, devices)
	inputs, unsupported, err := executionInputsDigest(config, devices, configFile)
	if err != nil {
		return runManifest{}, err
	}
	manifest := runManifest{FormatVersion: 2, InputsDigest: inputs, ResumeUnsupported: unsupported, RunID: runID, CreatedAt: time.Now().UTC(), ConfigDigest: configDigest, InventoryDigest: inventoryDigest, PlanDigest: plan.ResolutionDigest}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return runManifest{}, err
	}
	path, err := resolveWriteWithin(runDir, runManifestFilename)
	if err != nil {
		return runManifest{}, err
	}
	if err := atomicWriteFile(path, append(encoded, '\n')); err != nil {
		return runManifest{}, err
	}
	return manifest, nil
}

func loadRunManifest(runDir string) (runManifest, error) {
	path, err := resolveWriteWithin(runDir, runManifestFilename)
	if err != nil {
		return runManifest{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return runManifest{}, err
	}
	var manifest runManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return runManifest{}, err
	}
	if manifest.FormatVersion != 2 || manifest.InputsDigest == "" || manifest.RunID == "" || manifest.ConfigDigest == "" || manifest.PlanDigest == "" {
		return runManifest{}, fmt.Errorf("invalid or obsolete run manifest: resume requires format version 2")
	}
	return manifest, nil
}

func verifyResumeManifest(runDir, configFile string, config Config, devices []DeviceConfig) (runManifest, error) {
	manifest, err := loadRunManifest(runDir)
	if err != nil {
		return runManifest{}, fmt.Errorf("load resume manifest: %w", err)
	}
	configDigest, err := fileDigest(configFile)
	if err != nil {
		return runManifest{}, err
	}
	inventoryPath := strings.TrimSpace(config.InventoryFile)
	if inventoryPath != "" {
		inventoryPath = resolveInventoryPath(inventoryPath, configFile)
	}
	inventoryDigest, err := fileDigest(inventoryPath)
	if err != nil {
		return runManifest{}, err
	}
	inputs, unsupported, err := executionInputsDigest(config, devices, configFile)
	if err != nil {
		return runManifest{}, err
	}
	if manifest.ResumeUnsupported != "" || unsupported != "" {
		return runManifest{}, fmt.Errorf("resume is unavailable for runtime-selected payload files; use inline payloads or static paths")
	}
	actualPlan := buildOfflinePlan(config, devices).ResolutionDigest
	differences := []string{}
	if manifest.InputsDigest != inputs {
		differences = append(differences, "execution inputs")
	}
	if manifest.ConfigDigest != configDigest {
		differences = append(differences, "config")
	}
	if manifest.InventoryDigest != inventoryDigest {
		differences = append(differences, "inventory")
	}
	if manifest.PlanDigest != actualPlan {
		differences = append(differences, "plan")
	}
	if len(differences) > 0 {
		return runManifest{}, fmt.Errorf("resume manifest does not match current %s digest(s)", strings.Join(differences, ", "))
	}
	return manifest, nil
}

func uncertainJournalEntries(runDir string) ([]runJournalEntry, error) {
	path, err := resolveWriteWithin(runDir, runJournalFilename)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries := map[string]runJournalEntry{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry runJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode run journal: %w", err)
		}
		key := journalEntryKey(entry)
		switch entry.State {
		case "intent":
			entries[key] = entry
		case "completed":
			delete(entries, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	uncertain := make([]runJournalEntry, 0, len(entries))
	for _, entry := range entries {
		uncertain = append(uncertain, entry)
	}
	sort.Slice(uncertain, func(i, k int) bool {
		return uncertain[i].Hostname+uncertain[i].Step < uncertain[k].Hostname+uncertain[k].Step
	})
	return uncertain, nil
}

func journalEntryKey(entry runJournalEntry) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", entry.Hostname, entry.IP, entry.Step, entry.Occurrence, entry.ExecutionID)
}

func completedJournalEntries(runDir string) (map[string]string, error) {
	path, err := resolveWriteWithin(runDir, runJournalFilename)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	completed := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry runJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode run journal: %w", err)
		}
		if entry.State == "completed" {
			completed[journalEntryKey(entry)] = entry.InputDigest
		} else if entry.State == "intent" {
			delete(completed, journalEntryKey(entry))
		}
	}
	return completed, scanner.Err()
}

// resumableMutationKind is intentionally conservative. Any imperative SSH
// command is treated as a mutation because its safety cannot be inferred from
// vendor syntax. Read-only NETCONF operations do not need a write-ahead
// record; all other NETCONF actions and declarative ensure operations do.
func resumableMutationKind(step StepConfig) string {
	if step.Ensure != nil {
		return "ensure"
	}
	if step.NETCONF != nil {
		op := strings.ToLower(strings.TrimSpace(step.NETCONF.Operation))
		if op == "get" || op == "get-config" || op == "validate" {
			return ""
		}
		return "netconf"
	}
	if strings.TrimSpace(step.Command) != "" {
		return "ssh_command"
	}
	return ""
}

func bytesDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Bind resume to resolved execution data and file contents, without storing their values.
func executionInputsDigest(config Config, devices []DeviceConfig, configFile string) (string, string, error) {
	files := map[string]string{}
	for path, digest := range config.inputDigests {
		files[path] = digest
	}
	parserPath := resolveParsersPath(config.ParsersFile, configFile)
	if _, err := os.Stat(parserPath); err == nil {
		digest, e := fileDigest(parserPath)
		if e != nil {
			return "", "", e
		}
		files[parserPath] = digest
	} else if !os.IsNotExist(err) || config.ParsersFile != "" {
		return "", "", err
	}
	base := config.baseDir
	if base == "" {
		base = filepath.Dir(configFile)
	}
	unsupported := ""
	var visit func(reflect.Value) error
	visit = func(v reflect.Value) error {
		if !v.IsValid() {
			return nil
		}
		if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			return visit(v.Elem())
		}
		if v.Type() == reflect.TypeOf(NETCONFStepConfig{}) {
			path := v.FieldByName("PayloadFile").String()
			if strings.Contains(path, "{{") {
				unsupported = "runtime payload path"
				return nil
			}
			if path != "" {
				resolved, err := resolveReadWithin(base, path)
				if err != nil {
					return err
				}
				digest, err := fileDigest(resolved)
				if err != nil {
					return err
				}
				files[resolved] = digest
			}
			return nil
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					if err := visit(v.Field(i)); err != nil {
						return err
					}
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				if err := visit(v.Index(i)); err != nil {
					return err
				}
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				if err := visit(it.Value()); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(reflect.ValueOf(config)); err != nil {
		return "", "", err
	}
	if err := visit(reflect.ValueOf(devices)); err != nil {
		return "", "", err
	}
	data, err := json.Marshal(struct {
		Config  Config
		Devices []DeviceConfig
		Files   map[string]string
	}{config, devices, files})
	if err != nil {
		return "", "", err
	}
	return bytesDigest(data), unsupported, nil
}

func executionID(ctx *stepExecutionContext) string { return bytesDigest([]byte(ctx.executionPath)) }

func executionBinding(ctx *stepExecutionContext) string {
	// Hash exact bytes, including invalid UTF-8 from device output. JSON would
	// replace invalid bytes and could collapse distinct runtime bindings.
	keys := make([]string, 0, len(ctx.variables))
	for key := range ctx.variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		value := ctx.variables[key]
		_, _ = fmt.Fprintf(hash, "%d:%s%d:%s", len(key), key, len(value), value)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
