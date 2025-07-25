package transport

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response"
	transportAuthenticatorAssertionResponse "github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response/transport"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response"
	transportAuthenticatorAttestationResponse "github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response/transport"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type TransportPublicKeyCredential[T transportAuthenticatorAttestationResponse.TransportAuthenticatorAttestationResponse | transportAuthenticatorAssertionResponse.TransportAuthenticatorAssertionResponse] struct {
	Id              transport.Base64URL `json:"id,omitempty"`
	Type            string              `json:"type,omitempty"`
	RawId           transport.Base64URL `json:"rawId,omitempty"`
	Response        T                   `json:"response,omitempty"`
	ClientExtension map[string]any      `json:"clientExtension,omitempty"`
}

func MakeAttestationPublicKeyCredential(
	transportCredential *TransportPublicKeyCredential[transportAuthenticatorAttestationResponse.TransportAuthenticatorAttestationResponse],
) (*public_key_credential.PublicKeyCredential[authenticator_attestation_response.AuthenticatorAttestationResponse], error) {
	if transportCredential == nil {
		return nil, nil
	}

	transportResponse := transportCredential.Response
	authenticatorResponse, err := transportResponse.MakeAuthenticatorResponse()
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("transport make authenticator response: %w", err),
			transportResponse,
		)
	}

	return &public_key_credential.PublicKeyCredential[authenticator_attestation_response.AuthenticatorAttestationResponse]{
		Id:              transportCredential.Id,
		Type:            transportCredential.Type,
		RawId:           transportCredential.RawId,
		Response:        *authenticatorResponse,
		ClientExtension: transportCredential.ClientExtension,
	}, nil
}

func MakeAssertionPublicKeyCredential(
	transportCredential *TransportPublicKeyCredential[transportAuthenticatorAssertionResponse.TransportAuthenticatorAssertionResponse],
) (*public_key_credential.PublicKeyCredential[authenticator_assertion_response.AuthenticatorAssertionResponse], error) {
	if transportCredential == nil {
		return nil, nil
	}

	transportResponse := transportCredential.Response
	authenticatorResponse, err := transportResponse.MakeAuthenticatorResponse()
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("transport make authenticator response: %w", err),
			transportResponse,
		)
	}

	return &public_key_credential.PublicKeyCredential[authenticator_assertion_response.AuthenticatorAssertionResponse]{
		Id:              transportCredential.Id,
		Type:            transportCredential.Type,
		RawId:           transportCredential.RawId,
		Response:        *authenticatorResponse,
		ClientExtension: transportCredential.ClientExtension,
	}, nil
}
