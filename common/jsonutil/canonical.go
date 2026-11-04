package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Canonical returns JSON with stable object ordering and formatting. Numbers
// remain json.Number so large integer configuration values are never rounded.
// Array order and numeric values remain significant.
func Canonical(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid character after top-level JSON value")
	}
	return json.Marshal(value)
}
