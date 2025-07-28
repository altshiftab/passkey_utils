package transport

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	transportAuthenticatorAssertionResponse "github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response/transport"
	transportAuthenticatorAttestationResponse "github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response/transport"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type AssertionPublicKeyCredential = PublicKeyCredential[transportAuthenticatorAssertionResponse.AuthenticatorAssertionResponse]
type AttestationPublicKeyCredential = PublicKeyCredential[transportAuthenticatorAttestationResponse.AuthenticatorAttestationResponse]

type PublicKeyCredential[T transportAuthenticatorAttestationResponse.AuthenticatorAttestationResponse | transportAuthenticatorAssertionResponse.AuthenticatorAssertionResponse] struct {
	Id              *transport.Base64URL `json:"id" required:"true" minLength:"1"`
	Type            string               `json:"type" required:"true" minLength:"1"`
	RawId           *transport.Base64URL `json:"rawId" required:"true" minLength:"1"`
	Response        T                    `json:"response" required:"true" minLength:"1"`
	ClientExtension map[string]any       `json:"clientExtension,omitempty"`
}

func MakeAttestationPublicKeyCredential(
	transportCredential *AttestationPublicKeyCredential,
) (*public_key_credential.AttestationPublicKeyCredential, error) {
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

	return &public_key_credential.AttestationPublicKeyCredential{
		Id:              *transportCredential.Id,
		Type:            transportCredential.Type,
		RawId:           *transportCredential.RawId,
		Response:        *authenticatorResponse,
		ClientExtension: transportCredential.ClientExtension,
	}, nil
}

func MakeAssertionPublicKeyCredential(
	transportCredential *AssertionPublicKeyCredential,
) (*public_key_credential.AssertionPublicKeyCredential, error) {
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

	return &public_key_credential.AssertionPublicKeyCredential{
		Id:              *transportCredential.Id,
		Type:            transportCredential.Type,
		RawId:           *transportCredential.RawId,
		Response:        *authenticatorResponse,
		ClientExtension: transportCredential.ClientExtension,
	}, nil
}
