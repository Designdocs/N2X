package conf

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Designdocs/N2X/common/json5"
)

// ValidateOptions carries what validation cannot learn from the file itself.
type ValidateOptions struct {
	// CoreTypes lists the core types compiled into the running binary. Empty
	// skips that check.
	CoreTypes []string
}

// IssueKind sorts problems so an operator can tell a broken file from a wrong
// value at a glance.
type IssueKind int

const (
	// IssueConfig is a well-formed file with a wrong key or value.
	IssueConfig IssueKind = iota
	// IssueSyntax is a file that is not valid JSON: a stray character, a
	// missing bracket or a duplicate key.
	IssueSyntax
	// IssueCert is a problem in a node's certificate settings.
	IssueCert
)

// Issue is one problem found in a config file. Path locates it the way the
// operator wrote it, e.g. "Nodes[2].CertConfig.CertDomain".
type Issue struct {
	Path    string
	Message string
	Kind    IssueKind
	// onReload is set on warnings: the message to reject a hot reload with
	// when the running config does not have this problem yet.
	onReload string
}

func (i Issue) String() string {
	if i.Path == "" {
		return i.Message
	}
	return i.Path + ": " + i.Message
}

// ValidationError lists every problem found in a config file, so a single
// run shows everything that has to be fixed. Warnings are the problems found
// alongside that would not have stopped the config on their own.
type ValidationError struct {
	File     string
	Issues   []Issue
	Warnings []Issue
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "config file %s has %d problem(s) (array indexes start at 0):", e.File, len(e.Issues))
	writeIssues(&b, e.Issues)
	if len(e.Warnings) > 0 {
		fmt.Fprintf(&b, "\nand %d warning(s):", len(e.Warnings))
		writeIssues(&b, e.Warnings)
	}
	return b.String()
}

func writeIssues(b *strings.Builder, issues []Issue) {
	for _, issue := range issues {
		b.WriteString("\n  - ")
		b.WriteString(issue.String())
	}
}

// LoadValidated loads filePath only if the whole file is valid: well-formed
// JSON, no duplicate or unknown keys, every environment variable resolvable,
// every value within range and every referenced file present. Nothing is
// started from a config that fails here, so a typo cannot half-apply or end
// up spending certificate quota. The one exception is the xray DNS file: a
// problem there only costs xray its DNS settings, so it is returned in
// Conf.Warnings instead.
func LoadValidated(filePath string, opts ValidateOptions) (*Conf, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("open config file error: %w", err)
	}
	v := &validator{opts: opts, nodeBodies: map[string]map[string]any{}}

	tree, ok := v.parseJSON5("", raw)
	if !ok {
		return nil, v.result(filePath)
	}
	resolved := v.resolveEnv("", tree)
	v.checkRoot(resolved)

	data, err := jsonv2.Marshal(resolved)
	if err != nil {
		return nil, fmt.Errorf("encode resolved config: %w", err)
	}
	c := New()
	if err := c.decode(data); err != nil {
		if !errors.Is(err, ErrMissingEnvVar) || len(v.issues) == 0 {
			v.addDecodeError(err)
		}
		return nil, v.result(filePath)
	}
	v.checkConf(c)
	if err := v.result(filePath); err != nil {
		return nil, err
	}
	c.Warnings = v.warnings
	return c, nil
}

type validator struct {
	opts     ValidateOptions
	issues   []Issue
	warnings []Issue
	// envPaths holds values that came from a missing environment variable;
	// rules skip them because their real value is unknown.
	envPaths map[string]bool
	// nodeBodies maps "Nodes[i]" to the object the node is decoded from:
	// the entry itself, or the contents of its Include file.
	nodeBodies map[string]map[string]any
}

func (v *validator) add(path, format string, args ...any) {
	kind := IssueConfig
	if isCertPath(path) {
		kind = IssueCert
	}
	v.addKind(kind, path, format, args...)
}

func (v *validator) addKind(kind IssueKind, path, format string, args ...any) {
	if v.envPaths[path] {
		return
	}
	v.issues = append(v.issues, Issue{Path: path, Message: fmt.Sprintf(format, args...), Kind: kind})
}

// isCertPath reports whether path lies inside a CertConfig block.
func isCertPath(path string) bool {
	for segment := range strings.SplitSeq(path, ".") {
		if segment == "CertConfig" {
			return true
		}
	}
	return false
}

func (v *validator) result(file string) error {
	if len(v.issues) == 0 {
		return nil
	}
	return &ValidationError{File: file, Issues: v.issues, Warnings: v.warnings}
}

// asWarnings runs check and turns the issues it adds into warnings. onStart
// says what happens when the config starts with the problem anyway, onReload
// why a hot reload that would bring the problem in is rejected instead.
func (v *validator) asWarnings(onStart, onReload string, check func()) {
	before := len(v.issues)
	check()
	for _, issue := range v.issues[before:] {
		issue.onReload = issue.Message + " (" + onReload + ")"
		issue.Message += " (" + onStart + ")"
		v.warnings = append(v.warnings, issue)
	}
	v.issues = v.issues[:before]
}

// newWarnings returns, as issues carrying their reload message, the warnings
// of next at a path none of the running warnings is at: problems a reload to
// next would bring in rather than keep.
func newWarnings(running, next []Issue) []Issue {
	var added []Issue
	for _, warning := range next {
		if slices.ContainsFunc(running, func(r Issue) bool { return r.Path == warning.Path }) {
			continue
		}
		message := warning.onReload
		if message == "" {
			message = warning.Message
		}
		added = append(added, Issue{Path: warning.Path, Message: message, Kind: warning.Kind})
	}
	return added
}

// parseJSON5 strips comments and trailing commas and parses what is left
// strictly. Problems are reported at path, with line numbers of raw.
// keepNumbers decodes JSON numbers into an any as their literal text, so
// re-encoding the tree cannot round integers above 2^53 through float64.
var keepNumbers = jsonv2.WithUnmarshalers(jsonv2.UnmarshalFromFunc(func(dec *jsontext.Decoder, value *any) error {
	if dec.PeekKind() != '0' {
		return jsonv2.SkipFunc
	}
	number, err := dec.ReadValue()
	if err != nil {
		return err
	}
	*value = jsontext.Value(number.Clone())
	return nil
}))

func (v *validator) parseJSON5(path string, raw []byte) (any, bool) {
	trimmed, err := io.ReadAll(json5.NewTrimNodeReader(bytes.NewReader(raw)))
	if err != nil {
		v.addKind(IssueSyntax, path, "read error: %v", err)
		return nil, false
	}
	var tree any
	if err := jsonv2.Unmarshal(trimmed, &tree, keepNumbers); err != nil {
		// Trimming blanks bytes out instead of removing them, so offsets in
		// trimmed are offsets in raw.
		v.addSyntaxError(path, raw, err)
		return nil, false
	}
	return tree, true
}

func (v *validator) addSyntaxError(path string, raw []byte, err error) {
	var syntaxErr *jsontext.SyntacticError
	if !errors.As(err, &syntaxErr) {
		v.addKind(IssueSyntax, path, "invalid JSON: %v", err)
		return
	}
	line, column := lineColumn(raw, syntaxErr.ByteOffset)
	where := joinPath(path, pointerPath(syntaxErr.JSONPointer))
	if errors.Is(err, jsontext.ErrDuplicateName) {
		v.addKind(IssueSyntax, where, "duplicate key (line %d, column %d); remove one of them", line, column)
		return
	}
	v.addKind(IssueSyntax, where, "invalid JSON at line %d, column %d: %v", line, column, syntaxErr.Err)
}

func (v *validator) addDecodeError(err error) {
	var semanticErr *jsonv2.SemanticError
	if !errors.As(err, &semanticErr) {
		v.add("", "cannot decode config: %v", err)
		return
	}
	if semanticErr.Err != nil {
		v.add(pointerPath(semanticErr.JSONPointer), "wrong value type: %v", semanticErr.Err)
		return
	}
	v.add(pointerPath(semanticErr.JSONPointer), "wrong value type: %v", err)
}

// resolveEnv returns a copy of tree with ${VAR} placeholders substituted. A
// missing variable is reported and replaced by "" so the rest of the file can
// still be checked. Keys starting with "_" are comments and never reported.
func (v *validator) resolveEnv(path string, tree any) any {
	return v.resolveEnvValue(path, tree, false)
}

func (v *validator) resolveEnvValue(path string, value any, comment bool) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = v.resolveEnvValue(joinPath(path, key), child, comment || strings.HasPrefix(key, "_"))
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = v.resolveEnvValue(indexPath(path, i), child, comment)
		}
		return out
	case string:
		resolved, err := substEnvString(typed)
		if err == nil {
			return resolved
		}
		if !comment {
			v.add(path, "environment variable is not set: %v (set it, or give a default like ${VAR:-value})", err)
			if v.envPaths == nil {
				v.envPaths = map[string]bool{}
			}
			v.envPaths[path] = true
		}
		return ""
	default:
		return value
	}
}

// decode fills p from JSON that has already been through json5 trimming.
func (p *Conf) decode(data []byte) error {
	resolved, err := resolveEnvPlaceholders(data)
	if err != nil {
		if !errors.Is(err, ErrMissingEnvVar) {
			return fmt.Errorf("resolve env placeholders error: %w", err)
		}
		// Fall back to the raw values; nodes resolve their own placeholders.
		resolved = data
	}
	return jsonv2.Unmarshal(resolved, p)
}

func lineColumn(raw []byte, offset int64) (int, int) {
	if offset > int64(len(raw)) {
		offset = int64(len(raw))
	}
	before := raw[:offset]
	line := bytes.Count(before, []byte("\n")) + 1
	column := len(before) - bytes.LastIndexByte(before, '\n')
	return line, column
}

// pointerPath renders a JSON pointer as Nodes[0].CertConfig. Numeric tokens
// are shown as indexes, which is what they are everywhere in this file.
func pointerPath(pointer jsontext.Pointer) string {
	path := ""
	for token := range pointer.Tokens() {
		if index, err := strconv.Atoi(token); err == nil && index >= 0 {
			path = indexPath(path, index)
			continue
		}
		path = joinPath(path, token)
	}
	return path
}

func joinPath(path, key string) string {
	switch {
	case path == "":
		return key
	case key == "":
		return path
	}
	return path + "." + key
}

func indexPath(path string, index int) string {
	return path + "[" + strconv.Itoa(index) + "]"
}

// decodeLegacy decodes with encoding/json v1 semantics (case-insensitive
// keys), which is how every block below Cores and Nodes is read.
func decodeLegacy(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
