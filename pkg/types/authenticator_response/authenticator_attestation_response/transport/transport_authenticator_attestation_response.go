package transport

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response"
	"github.com/altshiftab/passkey_utils/pkg/types/collected_client_data"
	transportCollectedClientData "github.com/altshiftab/passkey_utils/pkg/types/collected_client_data/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

// TODO: Add JSON schema notations.

type TransportAuthenticatorAttestationResponse struct {
	ClientDataJson     transport.Base64URL `json:"clientDataJSON,omitempty"`
	Transports         []string            `json:"transports,omitempty"`
	AuthenticatorData  transport.Base64URL `json:"authenticatorData,omitempty"`
	AttestationObject  transport.Base64URL `json:"attestationObject,omitempty"`
	PublicKey          transport.Base64URL `json:"publicKey,omitempty"`
	PublicKeyAlgorithm int                 `json:"publicKeyAlgorithm,omitempty"`
}

func (t TransportAuthenticatorAttestationResponse) GetClientDataJson() []byte {
	return t.ClientDataJson
}

func (t TransportAuthenticatorAttestationResponse) GetAuthenticatorData() []byte {
	return t.AuthenticatorData
}

func (t TransportAuthenticatorAttestationResponse) MakeAuthenticatorResponse() (*authenticator_attestation_response.AuthenticatorAttestationResponse, error) {
	clientDataJson := t.ClientDataJson
	collectedClientData, err := transportCollectedClientData.FromBytes(clientDataJson)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("transport collected client data from bytes: %w", err),
			clientDataJson,
		)
	}
	rawAuthenticatorData := t.AuthenticatorData
	authenticatorData, err := authenticator_data.FromBytes(rawAuthenticatorData)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("authenticator data from bytes: %w", err),
			rawAuthenticatorData,
		)
	}

	return &authenticator_attestation_response.AuthenticatorAttestationResponse{
		ClientDataJson: collected_client_data.CollectedClientData{
			Type:        collectedClientData.Type,
			Challenge:   collectedClientData.Challenge,
			Origin:      collectedClientData.Origin,
			CrossOrigin: collectedClientData.CrossOrigin,
			TopOrigin:   collectedClientData.TopOrigin,
		},
		Transports:         t.Transports,
		AuthenticatorData:  *authenticatorData,
		AttestationObject:  t.AttestationObject,
		PublicKey:          t.PublicKey,
		PublicKeyAlgorithm: t.PublicKeyAlgorithm,
	}, nil
}
