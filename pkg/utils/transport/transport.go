package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

type Base64URL []byte

func (b *Base64URL) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal: %w", err))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("base64 url encoding decode string: %w", err), encoded)
	}

	*b = decoded
	return nil
}

func (b *Base64URL) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(*b)
	data, err := json.Marshal(encoded)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), encoded)
	}

	return data, nil
}
