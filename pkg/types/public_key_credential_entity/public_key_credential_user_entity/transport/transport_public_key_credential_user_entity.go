package transport

import "github.com/altshiftab/passkey_utils/pkg/utils/transport"

// TODO Add JSON schema attributes.

type TransportPublicKeyCredentialUserEntity struct {
	Name        string              `json:"name"`
	Id          transport.Base64URL `json:"id"`
	DisplayName string              `json:"displayName"`
}

func (u *TransportPublicKeyCredentialUserEntity) GetName() string {
	return u.Name
}
