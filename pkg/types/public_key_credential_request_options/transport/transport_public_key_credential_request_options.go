package transport

import (
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_descriptor"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type PublicKeyCredentialRequestOptions struct {
	Challenge          *transport.Base64URL                                              `json:"challenge"`
	Timeout            uint64                                                            `json:"timeout,omitempty"`
	RpId               string                                                            `json:"rpId,omitempty"`
	AllowedCredentials []*public_key_credential_descriptor.PublicKeyCredentialDescriptor `json:"allowedCredentials,omitempty"`
	UserVerification   string                                                            `json:"userVerification,omitempty"`
	Extensions         map[string]any                                                    `json:"extensions,omitempty"`
}
