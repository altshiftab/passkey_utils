package transport

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalTransportPublicKeyCredentialCreationOptions(t *testing.T) {
	const input = `
		{
		  "challenge": "Z7IN7MdOR5o0dkDHomcmxUHh3dr7vO3SL1X_NUnD_a94-CV-TxVXjQ4LmpBa6pvImqiWYD5eKaG48MksNaOVpQ",
		  "rp": {
			"name": "Alt-Shift Login",
			"id": "alt-shift.se"
		  },
		  "user": {
			"id": "YjdiYmFhMTQtMmQzZS00ZTQyLWI1NjUtZmJhYTFkOWM1MmQ1",
			"name": "v@example.com",
			"displayName": "Please"
		  },
		  "pubKeyCredParams": [
			{
			  "type": "public-key",
			  "alg": -7
			}
		  ],
		  "authenticatorSelection": {
			"authenticatorAttachment": "platform",
			"residentKey": "required",
			"requireResidentKey": true
		  },
		  "attestation": "none"
		}
	`

	var transportPublicKeyCredentialCreationOptions TransportPublicKeyCredentialCreationOptions

	err := json.Unmarshal([]byte(input), &transportPublicKeyCredentialCreationOptions)
	if err != nil {
		t.Error(err)
	}
}
