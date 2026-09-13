package conf

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
)

// The schema check reports keys the decoder would silently ignore: a
// misspelled key otherwise leaves its setting at the default with no sign of
// why. Allowed keys are read from the config structs' json tags so the check
// cannot drift from what is actually decoded.

type schemaField struct {
	name string
	typ  reflect.Type
}

var (
	rawMessageType  = reflect.TypeFor[json.RawMessage]()
	coreConfigType  = reflect.TypeFor[CoreConfig]()
	nodeConfigType  = reflect.TypeFor[NodeConfig]()
	optionsType     = reflect.TypeFor[Options]()
	certConfigType  = reflect.TypeFor[CertConfig]()
	apiConfigFields = structFields(reflect.TypeFor[ApiConfig]())
)

// Options keys the decoder fills itself; values written by hand are dropped.
var derivedOptionKeys = []string{"RawOptions", "XrayOptions", "SingOptions"}

func structFields(t reflect.Type) []schemaField {
	fields := make([]schemaField, 0, t.NumField())
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, schemaField{name: name, typ: field.Type})
	}
	return fields
}

func (v *validator) checkRoot(tree any) {
	root, ok := tree.(map[string]any)
	if !ok {
		v.add("", "the config file must be a JSON object")
		return
	}
	// Conf and LogConfig are decoded by encoding/json/v2, which matches key
	// names exactly.
	v.checkObject("", root, structFields(reflect.TypeFor[Conf]()), false)
}

func (v *validator) checkValue(path string, value any, t reflect.Type, fold bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t {
	case rawMessageType:
		return
	case coreConfigType:
		v.checkCore(path, value)
		return
	case nodeConfigType:
		v.checkNode(path, value)
		return
	case optionsType:
		if object, ok := value.(map[string]any); ok {
			v.checkObject(path, object, optionFields(stringKey(object, "Core")), true)
		}
		return
	case certConfigType:
		t = reflect.TypeFor[certConfigJSON]()
	}
	switch t.Kind() {
	case reflect.Struct:
		if object, ok := value.(map[string]any); ok {
			v.checkObject(path, object, structFields(t), fold)
		}
	case reflect.Slice, reflect.Array:
		if array, ok := value.([]any); ok {
			for i, element := range array {
				v.checkValue(indexPath(path, i), element, t.Elem(), fold)
			}
		}
	case reflect.Map:
		if object, ok := value.(map[string]any); ok {
			for _, key := range sortedKeys(object) {
				v.checkValue(joinPath(path, key), object[key], t.Elem(), fold)
			}
		}
	}
}

// checkObject reports unknown keys in object and descends into known ones.
// fold selects encoding/json v1 matching: exact name first, then any case.
func (v *validator) checkObject(path string, object map[string]any, fields []schemaField, fold bool) {
	used := map[string]string{}
	for _, key := range sortedKeys(object) {
		if strings.HasPrefix(key, "_") {
			continue
		}
		keyPath := joinPath(path, key)
		field, ok := matchField(fields, key, object[key], fold)
		if !ok {
			v.add(keyPath, "%s", unknownKeyMessage(key, fields, fold))
			continue
		}
		if previous, dup := used[field.name]; dup {
			v.add(keyPath, "duplicate of %q (key names are not case-sensitive here); keep only one", previous)
			continue
		}
		used[field.name] = key
		v.checkValue(keyPath, object[key], field.typ, fold)
	}
}

// matchField finds the field key decodes into. The same name can appear
// twice when fields of several structs are merged (FallBackConfigs is a list
// for xray and an object for sing); the JSON value decides which applies.
func matchField(fields []schemaField, key string, value any, fold bool) (schemaField, bool) {
	var candidates []schemaField
	for _, field := range fields {
		if field.name == key {
			candidates = append(candidates, field)
		}
	}
	if len(candidates) == 0 && fold {
		for _, field := range fields {
			if strings.EqualFold(field.name, key) {
				candidates = append(candidates, field)
			}
		}
	}
	if len(candidates) == 0 {
		return schemaField{}, false
	}
	for _, candidate := range candidates {
		if kindMatches(candidate.typ, value) {
			return candidate, true
		}
	}
	return candidates[0], true
}

func kindMatches(t reflect.Type, value any) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch value.(type) {
	case map[string]any:
		return t.Kind() == reflect.Struct || t.Kind() == reflect.Map
	case []any:
		return t.Kind() == reflect.Slice || t.Kind() == reflect.Array
	}
	return true
}

func unknownKeyMessage(key string, fields []schemaField, fold bool) string {
	if suggestion := suggestField(key, fields); suggestion != "" {
		if !fold && strings.EqualFold(suggestion, key) {
			return fmt.Sprintf("unknown key; did you mean %q? (key names are case-sensitive here)", suggestion)
		}
		return fmt.Sprintf("unknown key; did you mean %q?", suggestion)
	}
	return "unknown key (it would be ignored)"
}

func suggestField(key string, fields []schemaField) string {
	lowerKey := strings.ToLower(key)
	best, bestDistance := "", -1
	for _, field := range fields {
		distance := editDistance(lowerKey, strings.ToLower(field.name))
		if bestDistance < 0 || distance < bestDistance {
			best, bestDistance = field.name, distance
		}
	}
	limit := max(2, len(key)/3)
	if bestDistance < 0 || bestDistance > limit {
		return ""
	}
	return best
}

// editDistance is the optimal string alignment distance, so a swapped pair of
// letters ("Domian") counts as one edit.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	rows := make([][]int, len(ra)+1)
	for i := range rows {
		rows[i] = make([]int, len(rb)+1)
		rows[i][0] = i
	}
	for j := range rows[0] {
		rows[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			rows[i][j] = min(rows[i-1][j]+1, rows[i][j-1]+1, rows[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				rows[i][j] = min(rows[i][j], rows[i-2][j-2]+1)
			}
		}
	}
	return rows[len(ra)][len(rb)]
}

func (v *validator) checkCore(path string, value any) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	fields := structFields(reflect.TypeFor[CoreConfig]())
	switch stringKey(object, "Type") {
	case "xray":
		fields = append(fields, structFields(reflect.TypeFor[XrayConfig]())...)
	case "sing":
		fields = append(fields, structFields(reflect.TypeFor[SingConfig]())...)
	default:
		// The type itself is reported by the rules; which keys belong to an
		// unknown core cannot be told.
		return
	}
	v.checkObject(path, object, fields, true)
}

func (v *validator) checkNode(path string, value any) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	include := stringKey(object, "Include")
	if include == "" {
		v.nodeBodies[path] = object
		v.checkNodeBody(path, object)
		return
	}
	for _, key := range sortedKeys(object) {
		if !strings.HasPrefix(key, "_") && !strings.EqualFold(key, "Include") {
			v.add(joinPath(path, key), "ignored because Include is set; move it into %s", include)
		}
	}
	includePath := joinPath(path, "Include")
	raw, err := os.ReadFile(include)
	if err != nil {
		v.add(includePath, "cannot read include file: %v", err)
		return
	}
	tree, ok := v.parseJSON5(includePath, raw)
	if !ok {
		return
	}
	body, ok := v.resolveEnv(path, tree).(map[string]any)
	if !ok {
		v.add(includePath, "include file %s must contain a JSON object", include)
		return
	}
	v.nodeBodies[path] = body
	v.checkNodeBody(path, body)
}

// checkNodeBody mirrors NodeConfig.UnmarshalJSON: API settings come from an
// "ApiConfig" block when there is one and from the node itself otherwise,
// and options likewise from "Options".
func (v *validator) checkNodeBody(path string, body map[string]any) {
	fields := []schemaField{
		{name: "Include", typ: reflect.TypeFor[string]()},
		{name: "ApiConfig", typ: reflect.TypeFor[ApiConfig]()},
		{name: "Options", typ: optionsType},
	}
	if _, ok := lookupKey(body, "ApiConfig"); !ok {
		fields = append(fields, apiConfigFields...)
	}
	if _, ok := lookupKey(body, "Options"); !ok {
		fields = append(fields, optionFields(stringKey(body, "Core"))...)
	}
	v.checkObject(path, body, fields, true)
}

// optionFields lists the keys an options object accepts for core. A node
// without a core is decoded later for whichever core serves it, so it may
// carry options of either.
func optionFields(core string) []schemaField {
	fields := slices.DeleteFunc(structFields(optionsType), func(field schemaField) bool {
		return slices.Contains(derivedOptionKeys, field.name)
	})
	if core != "sing" {
		fields = append(fields, structFields(reflect.TypeFor[XrayOptions]())...)
	}
	if core != "xray" {
		fields = append(fields, structFields(reflect.TypeFor[SingOptions]())...)
	}
	return fields
}

// lookupKey finds key the way encoding/json v1 does: exact, then any case.
func lookupKey(object map[string]any, key string) (any, bool) {
	if value, ok := object[key]; ok {
		return value, true
	}
	for _, candidate := range sortedKeys(object) {
		if strings.EqualFold(candidate, key) {
			return object[candidate], true
		}
	}
	return nil, false
}

func stringKey(object map[string]any, key string) string {
	value, _ := lookupKey(object, key)
	text, _ := value.(string)
	return text
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
