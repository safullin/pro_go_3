package domain

import "testing"

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
