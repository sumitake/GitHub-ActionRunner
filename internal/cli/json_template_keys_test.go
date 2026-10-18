package cli

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestTemplateKeysPreserveDynamicMapNames(t *testing.T) {
	type entry struct {
		Value string `json:"value"`
	}
	type template struct {
		Labels  map[string]string `json:"labels"`
		Entries map[string]*entry `json:"entries"`
	}
	for name, document := range map[string]string{
		"distinct map names": `{"labels":{"CamelKey":"one","camelkey":"two","with.punctuation":"three"},"entries":{"AnyName":{"value":"four"},"OtherName":null}}`,
		"null maps":          `{"labels":null,"entries":null}`,
		"escaped map name":   `{"labels":{"\u0041nyName":"one"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTemplateKeys([]byte(document), reflect.TypeFor[template]()); err != nil {
				t.Fatal(err)
			}
			var got template
			if err := json.Unmarshal([]byte(document), &got); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, document := range map[string]string{
		"duplicate map key":  `{"labels":{"AnyName":"one","AnyName":"two"}}`,
		"escaped duplicate":  `{"labels":{"AnyName":"one","\u0041nyName":"two"}}`,
		"typed map value":    `{"entries":{"AnyName":{"Value":"hidden"}}}`,
		"duplicate in value": `{"entries":{"AnyName":{"value":"one","value":"two"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTemplateKeys([]byte(document), reflect.TypeFor[template]()); !errors.Is(err, ErrHostCommandFailed) {
				t.Fatalf("ambiguous map template accepted: %v", err)
			}
		})
	}
}
