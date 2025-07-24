package authenticator_assertion_response

import (
	"github.com/altshiftab/passkeys_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkeys_utils/pkg/types/collected_client_data"
)

type AuthenticatorAssertionResponse struct {
	ClientDataJson    *collected_client_data.CollectedClientData
	AuthenticatorData *authenticator_data.AuthenticatorData
	Signature         []byte
	UserHandle        []byte
}

func (a *AuthenticatorAssertionResponse) GetClientDataJson() *collected_client_data.CollectedClientData {
	return a.ClientDataJson
}

func (a *AuthenticatorAssertionResponse) GetAuthenticatorData() *authenticator_data.AuthenticatorData {
	return a.AuthenticatorData
}
