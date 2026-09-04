package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxSecretNameLength limits names of new or updated secrets in Unicode characters.
	MaxSecretNameLength = 255
	// MaxSecretMetadataLength limits metadata of new or updated secrets in Unicode characters.
	MaxSecretMetadataLength = 4096
)

// SecretKind identifies the kind of data stored in a secret.
type SecretKind int32

const (
	// SecretKindCredentials represents a login and password pair.
	SecretKindCredentials SecretKind = 1
	// SecretKindText represents arbitrary text.
	SecretKindText SecretKind = 2
	// SecretKindBinary represents arbitrary binary data.
	SecretKindBinary SecretKind = 3
	// SecretKindCard represents bank card details.
	SecretKindCard SecretKind = 4
)

// String returns the command-line name of a secret kind.
func (k SecretKind) String() string {
	switch k {
	case SecretKindCredentials:
		return "credentials"
	case SecretKindText:
		return "text"
	case SecretKindBinary:
		return "binary"
	case SecretKindCard:
		return "card"
	default:
		return "unknown"
	}
}

// ParseSecretKind converts a command-line name to a secret kind.
func ParseSecretKind(value string) (SecretKind, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "credentials":
		return SecretKindCredentials, nil
	case "text":
		return SecretKindText, nil
	case "binary":
		return SecretKindBinary, nil
	case "card":
		return SecretKindCard, nil
	default:
		return 0, errors.New("unsupported secret kind")
	}
}

// Valid reports whether a secret kind is supported.
func (k SecretKind) Valid() bool {
	return k >= SecretKindCredentials && k <= SecretKindCard
}

// Secret is the encrypted representation stored by the server.
type Secret struct {
	ID         string
	UserID     string
	Kind       SecretKind
	Name       string
	Metadata   string
	Ciphertext []byte
	Nonce      []byte
	Version    int64
	Deleted    bool
	UpdatedAt  time.Time
}

// Payload contains decrypted user data and arbitrary metadata.
type Payload struct {
	Name        string       `json:"name"`
	Metadata    string       `json:"metadata,omitempty"`
	Credentials *Credentials `json:"credentials,omitempty"`
	Text        *TextData    `json:"text,omitempty"`
	Binary      *BinaryData  `json:"binary,omitempty"`
	Card        *CardData    `json:"card,omitempty"`
}

// Credentials contains a login and password pair.
type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// TextData contains arbitrary text.
type TextData struct {
	Value string `json:"value"`
}

// BinaryData contains arbitrary bytes and their original file name.
type BinaryData struct {
	FileName string `json:"file_name"`
	Data     []byte `json:"data"`
}

// CardData contains bank card details.
type CardData struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"`
	CVV    string `json:"cvv"`
}

// Validate checks that a payload matches its declared kind.
func (p Payload) Validate(kind SecretKind) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("secret name is required")
	}
	switch kind {
	case SecretKindCredentials:
		if p.Credentials == nil || p.Credentials.Login == "" || p.Credentials.Password == "" {
			return errors.New("login and password are required")
		}
	case SecretKindText:
		if p.Text == nil {
			return errors.New("text value is required")
		}
	case SecretKindBinary:
		if p.Binary == nil || p.Binary.FileName == "" {
			return errors.New("binary file is required")
		}
	case SecretKindCard:
		if p.Card == nil || p.Card.Number == "" || p.Card.Holder == "" || p.Card.Expiry == "" || p.Card.CVV == "" {
			return errors.New("card details are required")
		}
	default:
		return errors.New("unsupported secret kind")
	}
	return nil
}

// ValidateSecretMetadata checks the database limits before saving a secret.
func ValidateSecretMetadata(name, metadata string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("secret name is required")
	}
	if utf8.RuneCountInString(name) > MaxSecretNameLength {
		return fmt.Errorf("secret name must not exceed %d characters", MaxSecretNameLength)
	}
	if utf8.RuneCountInString(metadata) > MaxSecretMetadataLength {
		return fmt.Errorf("secret metadata must not exceed %d characters", MaxSecretMetadataLength)
	}
	return nil
}

// Entry combines encrypted record metadata with its decrypted payload.
type Entry struct {
	Secret  Secret
	Payload Payload
}
