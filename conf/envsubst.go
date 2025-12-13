package conf

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// resolveEnvPlaceholders replaces string values that are exactly in the form:
//
//	${VAR}           -> required env var
//	${VAR:-default}  -> env var or default if missing/empty
func resolveEnvPlaceholders(data []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	out, err := walkAndSubst(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func walkAndSubst(v any) (any, error) {
	switch vv := v.(type) {
	case map[string]any:
		for k, child := range vv {
			nv, err := walkAndSubst(child)
			if err != nil {
				return nil, err
			}
			vv[k] = nv
		}
		return vv, nil
	case []any:
		for i, child := range vv {
			nv, err := walkAndSubst(child)
			if err != nil {
				return nil, err
			}
			vv[i] = nv
		}
		return vv, nil
	case string:
		return substEnvString(vv)
	default:
		return v, nil
	}
}

func substEnvString(s string) (string, error) {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return s, nil
	}
	expr := strings.TrimSuffix(strings.TrimPrefix(s, "${"), "}")
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return s, nil
	}

	varName := expr
	defaultValue := ""
	hasDefault := false
	if left, right, ok := strings.Cut(expr, ":-"); ok {
		varName = strings.TrimSpace(left)
		defaultValue = right
		hasDefault = true
	}

	if varName == "" {
		return s, nil
	}
	if v, ok := os.LookupEnv(varName); ok && v != "" {
		return v, nil
	}
	if hasDefault {
		return defaultValue, nil
	}
	return "", fmt.Errorf("missing required env var: %s", varName)
}
