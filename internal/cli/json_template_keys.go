package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// Templates allow noncanonical formatting, but not duplicate decoded keys or
// case-insensitive struct-field aliases. String-map keys remain data.
func validateTemplateKeys(document []byte, schema reflect.Type) error {
	fields := make(map[string]reflect.Type)
	switch schema.Kind() {
	case reflect.Struct:
		for index := range schema.NumField() {
			field := schema.Field(index)
			key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			fields[key] = field.Type
		}
	case reflect.Map:
		if schema.Key().Kind() != reflect.String {
			return ErrHostCommandFailed
		}
	default:
		return ErrHostCommandFailed
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrHostCommandFailed
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		valueType := fields[key]
		if schema.Kind() == reflect.Map {
			valueType = schema.Elem()
		}
		if err != nil || !ok || valueType == nil || seen[key] {
			return ErrHostCommandFailed
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return ErrHostCommandFailed
		}
		if err := validateTemplateValueKeys(value, valueType); err != nil {
			return ErrHostCommandFailed
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return ErrHostCommandFailed
	}
	return nil
}

func validateTemplateValueKeys(value json.RawMessage, schema reflect.Type) error {
	// encoding/json accepts null for scalars and structs as well as pointers
	// and slices. Keep that behavior; the typed decoder and validators follow.
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil
	}
	for schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	switch schema.Kind() {
	case reflect.Struct, reflect.Map:
		return validateTemplateKeys(value, schema)
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(value, &values); err != nil {
			return ErrHostCommandFailed
		}
		for _, element := range values {
			if err := validateTemplateValueKeys(element, schema.Elem()); err != nil {
				return ErrHostCommandFailed
			}
		}
	}
	return nil
}
