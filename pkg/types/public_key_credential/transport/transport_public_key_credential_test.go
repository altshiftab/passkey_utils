package transport

import (
	"encoding/json"
	"fmt"
	transportAuthenticatorAssertionResponse "github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response/transport"
	transportAuthenticatorAttestationResponse "github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response/transport"
	"testing"
)

func TestUnmarshalAssertionTransportPublicKeyCredential(t *testing.T) {
	const input = `
		{
		  "authenticatorAttachment": "platform",
		  "clientExtensionResults": {},
		  "id": "AsDY91_hSwTVT8owaP_hfw",
		  "rawId": "AsDY91_hSwTVT8owaP_hfw",
		  "response": {
			"authenticatorData": "1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifMdAAAAAA",
			"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVJQTU9oTTczYnVIUmxuNXFQb2lkTjV2SFdzSGwtbDVEdTJxNWlwZmlrRm5UYWRLZGJXYTZFdkNMUlBYaUR1dnotWXNibnV3Y1NpbGhSTG44NERFelEiLCJvcmlnaW4iOiJodHRwczovL2xvZ2luLmFsdC1zaGlmdC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
			"signature": "MEQCIBCCQkxvytFK7GGjITF2san-K8nHPy3f2uTX3p9zqqtWAiAaEUiZTi0FmEfLvy6Su0k6rneI-mwXEK041d9qDsCTyA",
			"userHandle": "YjdiYmFhMTQtMmQzZS00ZTQyLWI1NjUtZmJhYTFkOWM1MmQ1"
		  },
		  "type": "public-key"
		}
	`

	var transportPublicKeyCredential TransportPublicKeyCredential[transportAuthenticatorAssertionResponse.TransportAuthenticatorAssertionResponse]

	err := json.Unmarshal([]byte(input), &transportPublicKeyCredential)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("rawClientDataJson := %#v\n", transportPublicKeyCredential.Response.ClientDataJson)
	fmt.Printf("rawAuthenticatorData := %#v\n", transportPublicKeyCredential.Response.AuthenticatorData)

	k, err := transportPublicKeyCredential.MakePublicKeyCredential()
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("challenge := %#v\n", k.Response.GetClientDataJson().Challenge)

}

func TestUnmarshalAttestationTransportPublicKeyCredential(t *testing.T) {
	const input = `
		{
		  "authenticatorAttachment": "platform",
		  "clientExtensionResults": {},
		  "id": "AsDY91_hSwTVT8owaP_hfw",
		  "rawId": "AsDY91_hSwTVT8owaP_hfw",
		  "response": {
			"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifNdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEALA2Pdf4UsE1U_KMGj_4X-lAQIDJiABIVggAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJMiWCC8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q",
			"authenticatorData": "1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifNdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEALA2Pdf4UsE1U_KMGj_4X-lAQIDJiABIVggAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJMiWCC8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q",
			"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWjdJTjdNZE9SNW8wZGtESG9tY214VUhoM2RyN3ZPM1NMMVhfTlVuRF9hOTQtQ1YtVHhWWGpRNExtcEJhNnB2SW1xaVdZRDVlS2FHNDhNa3NOYU9WcFEiLCJvcmlnaW4iOiJodHRwczovL2xvZ2luLmFsdC1zaGlmdC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
			"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJO8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q",
			"publicKeyAlgorithm": -7,
			"transports": [
			  "hybrid",
			  "internal"
			]
		  },
		  "type": "public-key"
		}
	`

	var transportPublicKeyCredential TransportPublicKeyCredential[transportAuthenticatorAttestationResponse.TransportAuthenticatorAttestationResponse]

	err := json.Unmarshal([]byte(input), &transportPublicKeyCredential)
	if err != nil {
		t.Error(err)
	}

	_, err = transportPublicKeyCredential.MakePublicKeyCredential()
	if err != nil {
		t.Error(err)
	}
}
