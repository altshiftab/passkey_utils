package transport

import (
	"fmt"
	"github.com/altshiftab/passkeys_utils/pkg/types/authenticator_response/authenticator_attestation_response"
	"github.com/altshiftab/passkeys_utils/pkg/types/collected_client_data"
	transportCollectedClientData "github.com/altshiftab/passkeys_utils/pkg/types/collected_client_data/transport"
	"github.com/altshiftab/passkeys_utils/pkg/utils/transport"
)

// TODO: Add JSON schema notations.

type TransportAuthenticatorAttestationResponse struct {
	ClientDataJson     transport.Base64URL `json:"clientDataJSON,omitempty"`
	AttestationObject  transport.Base64URL `json:"attestationObject,omitempty"`
	PublicKey          transport.Base64URL `json:"publicKey,omitempty"`
	PublicKeyAlgorithm int                 `json:"publicKeyAlgorithm,omitempty"`
}

func (t *TransportAuthenticatorAttestationResponse) MakeAuthenticatorResponse() (*authenticator_attestation_response.AuthenticatorAttestationResponse, error) {
	collectedClientData, err := transportCollectedClientData.FromBytes(t.ClientDataJson)
	if err != nil {
		return nil, fmt.Errorf("transport collected client data from bytes: %w", err)
	}

	return &authenticator_attestation_response.AuthenticatorAttestationResponse{
		ClientDataJson: &collected_client_data.CollectedClientData{
			Type:        collectedClientData.Type,
			Challenge:   collectedClientData.Challenge,
			Origin:      collectedClientData.Origin,
			CrossOrigin: collectedClientData.CrossOrigin,
			TopOrigin:   collectedClientData.TopOrigin,
		},
		AttestationObject:  t.AttestationObject,
		PublicKey:          t.PublicKey,
		PublicKeyAlgorithm: t.PublicKeyAlgorithm,
	}, nil
}
