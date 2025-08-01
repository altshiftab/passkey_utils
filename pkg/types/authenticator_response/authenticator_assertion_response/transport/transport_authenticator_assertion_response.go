package transport

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response"
	"github.com/altshiftab/passkey_utils/pkg/types/collected_client_data"
	transportCollectedClientData "github.com/altshiftab/passkey_utils/pkg/types/collected_client_data/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type AuthenticatorAssertionResponse struct {
	ClientDataJson    *transport.Base64URL `json:"clientDataJSON" required:"true" minLength:"1"`
	AuthenticatorData *transport.Base64URL `json:"authenticatorData" required:"true" minLength:"1"`
	Signature         *transport.Base64URL `json:"signature" required:"true" minLength:"1"`
	// NOTE: Not required in spec, but I don't see why it mustn't be.
	UserHandle        *transport.Base64URL `json:"userHandle,omitempty" required:"true" minLength:"1"`

	_ struct{} `additionalProperties:"false"`
}

func (t AuthenticatorAssertionResponse) GetClientDataJson() []byte {
	return *t.ClientDataJson
}

func (t AuthenticatorAssertionResponse) GetAuthenticatorData() []byte {
	return *t.AuthenticatorData
}

func (t AuthenticatorAssertionResponse) MakeAuthenticatorResponse() (*authenticator_assertion_response.AuthenticatorAssertionResponse, error) {
	collectedClientData, err := transportCollectedClientData.FromBytes(*t.ClientDataJson)
	if err != nil {
		return nil, fmt.Errorf("transport collected client data from bytes: %w", err)
	}
	if collectedClientData == nil {
		return nil, motmedelErrors.NewWithTrace(errors.ErrNilCollectedClientData)
	}

	authenticatorData, err := authenticator_data.FromBytes(*t.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("authenticator data from bytes: %w", err)
	}
	if authenticatorData == nil {
		return nil, motmedelErrors.NewWithTrace(errors.ErrNilAuthenticatorData)
	}

	return &authenticator_assertion_response.AuthenticatorAssertionResponse{
		ClientDataJson: collected_client_data.CollectedClientData{
			Type:        collectedClientData.Type,
			Challenge:   *collectedClientData.Challenge,
			Origin:      collectedClientData.Origin,
			CrossOrigin: collectedClientData.CrossOrigin,
			TopOrigin:   collectedClientData.TopOrigin,
		},
		AuthenticatorData: *authenticatorData,
		Signature:         *t.Signature,
		UserHandle:        *t.UserHandle,
	}, nil
}
