package transport

import (
	"encoding/json"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type CollectedClientData struct {
	Type        string               `json:"type" required:"true" minLength:"1"`
	Challenge   *transport.Base64URL `json:"challenge" required:"true" minLength:"1"`
	Origin      string               `json:"origin" required:"true" minLength:"1"`
	CrossOrigin bool                 `json:"crossOrigin,omitempty"`
	// NOTE: Not in spec.
	TopOrigin string `json:"topOrigin,omitempty"`
	// TODO: Add `TokenBinding`
}

func FromBytes(data []byte) (*CollectedClientData, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var transportCollectedClientData CollectedClientData
	if err := json.Unmarshal(data, &transportCollectedClientData); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal: %w", err))
	}

	return &transportCollectedClientData, nil
}
