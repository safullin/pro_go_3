package domain

import (
	"strings"
	"testing"
)

func TestSecretKinds(t *testing.T) {
	tests := []struct {
		name string
		kind SecretKind
	}{
		{name: "credentials", kind: SecretKindCredentials},
		{name: "text", kind: SecretKindText},
		{name: "binary", kind: SecretKindBinary},
		{name: "card", kind: SecretKindCard},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, err := ParseSecretKind(test.name)
			if err != nil || kind != test.kind || kind.String() != test.name || !kind.Valid() {
				t.Fatalf("unexpected kind conversion: %v %v", kind, err)
			}
		})
	}
	if _, err := ParseSecretKind("unknown"); err == nil {
		t.Fatal("expected unsupported kind error")
	}
	if SecretKind(100).String() != "unknown" || SecretKind(100).Valid() {
		t.Fatal("unexpected unknown kind behavior")
	}
}

func TestPayloadValidate(t *testing.T) {
	valid := []struct {
		kind    SecretKind
		payload Payload
	}{
		{SecretKindCredentials, Payload{Name: "site", Credentials: &Credentials{Login: "me", Password: "secret"}}},
		{SecretKindText, Payload{Name: "note", Text: &TextData{Value: "text"}}},
		{SecretKindBinary, Payload{Name: "file", Binary: &BinaryData{FileName: "a.bin"}}},
		{SecretKindCard, Payload{Name: "card", Card: &CardData{Number: "1", Holder: "A", Expiry: "01/30", CVV: "123"}}},
	}
	for _, test := range valid {
		if err := test.payload.Validate(test.kind); err != nil {
			t.Fatalf("valid payload rejected: %v", err)
		}
	}
	invalid := []struct {
		kind    SecretKind
		payload Payload
	}{
		{SecretKindText, Payload{}},
		{SecretKindCredentials, Payload{Name: "x"}},
		{SecretKindText, Payload{Name: "x"}},
		{SecretKindBinary, Payload{Name: "x"}},
		{SecretKindCard, Payload{Name: "x"}},
		{SecretKind(99), Payload{Name: "x"}},
	}
	for _, test := range invalid {
		if err := test.payload.Validate(test.kind); err == nil {
			t.Fatalf("invalid payload accepted: %+v", test)
		}
	}
}

func TestValidateSecretMetadata(t *testing.T) {
	for _, test := range []struct {
		name, secretName, metadata string
		wantError                  bool
	}{
		{name: "empty", wantError: true},
		{name: "blank", secretName: " \t", wantError: true},
		{name: "no metadata", secretName: "Note"},
		{name: "at limits", secretName: strings.Repeat("n", MaxSecretNameLength), metadata: strings.Repeat("m", MaxSecretMetadataLength)},
		{name: "unicode at limits", secretName: strings.Repeat("\u0438", MaxSecretNameLength), metadata: strings.Repeat("\u044f", MaxSecretMetadataLength)},
		{name: "long name", secretName: strings.Repeat("\u0438", MaxSecretNameLength+1), wantError: true},
		{name: "long metadata", secretName: "Note", metadata: strings.Repeat("\u044f", MaxSecretMetadataLength+1), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSecretMetadata(test.secretName, test.metadata)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}
