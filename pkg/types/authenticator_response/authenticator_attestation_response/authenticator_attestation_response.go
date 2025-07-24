package authenticator_attestation_response

import (
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkey_utils/pkg/types/collected_client_data"
)

type AuthenticatorAttestationResponse struct {
	ClientDataJson *collected_client_data.CollectedClientData
	// TODO: Parse?
	AttestationObject  []byte
	Transports         []string
	AuthenticatorData  *authenticator_data.AuthenticatorData
	PublicKey          []byte
	PublicKeyAlgorithm int
}

func (a *AuthenticatorAttestationResponse) GetClientDataJson() *collected_client_data.CollectedClientData {
	return a.ClientDataJson
}

func (a *AuthenticatorAttestationResponse) GetAuthenticatorData() *authenticator_data.AuthenticatorData {
	return a.AuthenticatorData
}
