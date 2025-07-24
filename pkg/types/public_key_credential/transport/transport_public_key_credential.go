package transport

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	passkeyUtilsErrors "github.com/altshiftab/passkeys_utils/pkg/errors"
	"github.com/altshiftab/passkeys_utils/pkg/types/authenticator_response"
	transportAuthenticatorAssertionResponse "github.com/altshiftab/passkeys_utils/pkg/types/authenticator_response/authenticator_assertion_response/transport"
	transportAuthenticatorAttestationResponse "github.com/altshiftab/passkeys_utils/pkg/types/authenticator_response/authenticator_attestation_response/transport"
	"github.com/altshiftab/passkeys_utils/pkg/types/public_key_credential"
	"github.com/altshiftab/passkeys_utils/pkg/utils/transport"
)

type TransportPublicKeyCredential[T transportAuthenticatorAssertionResponse.TransportAuthenticatorAssertionResponse | transportAuthenticatorAttestationResponse.TransportAuthenticatorAttestationResponse] struct {
	Id              transport.Base64URL `json:"id,omitempty"`
	Type            string              `json:"type,omitempty"`
	RawId           transport.Base64URL `json:"rawId,omitempty"`
	Response        *T                  `json:"response,omitempty"`
	ClientExtension map[string]any      `json:"clientExtension,omitempty"`
}

func (t *TransportPublicKeyCredential[T]) MakePublicKeyCredential() (*public_key_credential.PublicKeyCredential, error) {
	var authenticatorResponse authenticator_response.AuthenticatorResponse

	response := t.Response
	switch transportAuthenticatorResponse := any(response).(type) {
	case *transportAuthenticatorAssertionResponse.TransportAuthenticatorAssertionResponse:
		var err error
		authenticatorResponse, err = transportAuthenticatorResponse.MakeAuthenticatorResponse()
		if err != nil {
			return nil, motmedelErrors.New(
				fmt.Errorf("transport authenticator assertion response make authenticator response: %w", err),
				transportAuthenticatorResponse,
			)
		}
	case *transportAuthenticatorAttestationResponse.TransportAuthenticatorAttestationResponse:
		var err error
		authenticatorResponse, err = transportAuthenticatorResponse.MakeAuthenticatorResponse()
		if err != nil {
			return nil, motmedelErrors.New(
				fmt.Errorf("transport authenticator attestation response make authenticator response: %w", err),
			)
		}
	case nil:
	default:
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("%w: %T", passkeyUtilsErrors.ErrUnexpectedAuthenticatorResponseType, response),
			response,
		)
	}

	return &public_key_credential.PublicKeyCredential{
		Id:              t.Id,
		Type:            t.Type,
		RawId:           t.RawId,
		Response:        authenticatorResponse,
		ClientExtension: t.ClientExtension,
	}, nil
}
