package transport

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response"
	"github.com/altshiftab/passkey_utils/pkg/types/collected_client_data"
	transportCollectedClientData "github.com/altshiftab/passkey_utils/pkg/types/collected_client_data/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type AuthenticatorAttestationResponse struct {
	ClientDataJson     *transport.Base64URL `json:"clientDataJSON" required:"true" minLength:"1"`
	Transports         []string             `json:"transports" required:"true" minLength:"1"`
	AuthenticatorData  *transport.Base64URL `json:"authenticatorData" required:"true" minLength:"1"`
	AttestationObject  *transport.Base64URL `json:"attestationObject" required:"true" minLength:"1"`
	// NOTE: Not required according to spec, but I don't see why it mustn't be.
	PublicKey          *transport.Base64URL `json:"publicKey,omitempty" required:"true" minLength:"1"`
	PublicKeyAlgorithm int                  `json:"publicKeyAlgorithm" required:"true"`

	_ struct{} `additionalProperties:"false"`
}

func (t AuthenticatorAttestationResponse) GetClientDataJson() []byte {
	return *t.ClientDataJson
}

func (t AuthenticatorAttestationResponse) GetAuthenticatorData() []byte {
	return *t.AuthenticatorData
}

func (t AuthenticatorAttestationResponse) MakeAuthenticatorResponse() (*authenticator_attestation_response.AuthenticatorAttestationResponse, error) {
	clientDataJson := t.ClientDataJson
	collectedClientData, err := transportCollectedClientData.FromBytes(*clientDataJson)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("transport collected client data from bytes: %w", err),
			clientDataJson,
		)
	}
	if collectedClientData == nil {
		return nil, motmedelErrors.NewWithTrace(errors.ErrNilCollectedClientData)
	}

	rawAuthenticatorData := t.AuthenticatorData
	authenticatorData, err := authenticator_data.FromBytes(*rawAuthenticatorData)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("authenticator data from bytes: %w", err),
			rawAuthenticatorData,
		)
	}

	return &authenticator_attestation_response.AuthenticatorAttestationResponse{
		ClientDataJson: collected_client_data.CollectedClientData{
			Type:        collectedClientData.Type,
			Challenge:   *collectedClientData.Challenge,
			Origin:      collectedClientData.Origin,
			CrossOrigin: collectedClientData.CrossOrigin,
			TopOrigin:   collectedClientData.TopOrigin,
		},
		Transports:         t.Transports,
		AuthenticatorData:  *authenticatorData,
		AttestationObject:  *t.AttestationObject,
		PublicKey:          *t.PublicKey,
		PublicKeyAlgorithm: t.PublicKeyAlgorithm,
	}, nil
}
