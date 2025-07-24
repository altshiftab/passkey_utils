package public_key_credential_request_options

import (
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_descriptor"
)

type PublicKeyCredentialRequestOptions struct {
	Challenge          []byte                                                            `json:"challenge"`
	Timeout            uint64                                                            `json:"timeout,omitempty"`
	RpId               string                                                            `json:"rpId,omitempty"`
	AllowedCredentials []*public_key_credential_descriptor.PublicKeyCredentialDescriptor `json:"allowedCredentials,omitempty"`
	UserVerification   string                                                            `json:"userVerification,omitempty"`
	Extensions         map[string]any                                                    `json:"extensions,omitempty"`
}
