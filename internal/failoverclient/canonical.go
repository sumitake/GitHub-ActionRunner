package failoverclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const maxProtocolBytes = 65536

var ErrProtocolCodec = errors.New("failoverclient: protocol codec")

func CanonicalJSON(value any) ([]byte, error) {
	sorted, err := sortValue(value)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sorted)
	if err != nil || len(encoded) == 0 || len(encoded) > maxProtocolBytes {
		return nil, fmt.Errorf("%w: encode", ErrProtocolCodec)
	}
	return encoded, nil
}

func ParseCanonicalJSON(text []byte) (any, error) {
	if len(text) == 0 || len(text) > maxProtocolBytes {
		return nil, fmt.Errorf("%w: size", ErrProtocolCodec)
	}
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.UseNumber()
	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: decode", ErrProtocolCodec)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: trailing", ErrProtocolCodec)
	}
	encoded, err := CanonicalJSON(parsed)
	if err != nil || !bytes.Equal(encoded, text) {
		return nil, fmt.Errorf("%w: noncanonical", ErrProtocolCodec)
	}
	return parsed, nil
}

func sortValue(value any) (any, error) {
	switch typed := value.(type) {
	case nil, string, bool:
		return typed, nil
	case json.Number:
		if _, err := typed.Int64(); err == nil {
			return typed, nil
		}
		return nil, fmt.Errorf("%w: number", ErrProtocolCodec)
	case float64:
		if typed != float64(int64(typed)) {
			return nil, fmt.Errorf("%w: number", ErrProtocolCodec)
		}
		return json.Number(fmt.Sprintf("%d", int64(typed))), nil
	case int:
		return json.Number(fmt.Sprintf("%d", typed)), nil
	case int64:
		return json.Number(fmt.Sprintf("%d", typed)), nil
	case uint64:
		return json.Number(fmt.Sprintf("%d", typed)), nil
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			sorted, err := sortValue(item)
			if err != nil {
				return nil, err
			}
			out[i] = sorted
		}
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(keys))
		for _, key := range keys {
			sorted, err := sortValue(typed[key])
			if err != nil {
				return nil, err
			}
			out[key] = sorted
		}
		return out, nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return nil, fmt.Errorf("%w: type", ErrProtocolCodec)
		}
		var generic any
		if err := json.Unmarshal(encoded, &generic); err != nil {
			return nil, fmt.Errorf("%w: type", ErrProtocolCodec)
		}
		return sortValue(generic)
	}
}
