package authenticator_data

import (
	"encoding/binary"
	"errors"
)

type AttestedCredentialData struct {
	Aaguid       []byte
	CredentialId []byte
	PublicKey    []byte
}

type AuthenticatorData struct {
	RpIdHash           []byte
	Flags              byte
	SignCount          uint32
	AttestedCredential *AttestedCredentialData
	Extensions         []byte
}

// TODO: Fix errors

func FromBytes(data []byte) (*AuthenticatorData, error) {
	const (
		minAuthDataLength   = 37 // Minimum length: RP ID Hash (32) + Flags (1) + Signature Counter (4)
		aaguidLength        = 16 // Length of the AAGUID (16 bytes)
		credentialIdMinSize = 2  // Minimum 2 bytes for Credential ID Length (variable)
	)

	if len(data) < minAuthDataLength {
		return nil, errors.New("authenticator data is too short")
	}

	authenticatorData := &AuthenticatorData{
		RpIdHash:  data[:32],
		Flags:     data[32],
		SignCount: binary.BigEndian.Uint32(data[33:37]),
	}

	if authenticatorData.Flags&0x40 != 0 {
		offset := 37
		if len(data) < offset+aaguidLength {
			return nil, errors.New("authenticator data missing AAGUID")
		}

		aaguid := data[offset : offset+aaguidLength]
		offset += aaguidLength

		if len(data) < offset+credentialIdMinSize {
			return nil, errors.New("authenticator data missing Credential ID length")
		}
		credentialIdLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if len(data) < offset+credentialIdLength {
			return nil, errors.New("authenticator data credential ID length exceeds data size")
		}
		credentialId := data[offset : offset+credentialIdLength]
		offset += credentialIdLength

		if len(data) <= offset {
			return nil, errors.New("authenticator data missing public key")
		}
		publicKey := data[offset:]

		authenticatorData.AttestedCredential = &AttestedCredentialData{
			Aaguid:       aaguid,
			CredentialId: credentialId,
			PublicKey:    publicKey,
		}
	}

	// Parse extensions data if the ED flag is set (bit 7 of the Flags byte)
	if authenticatorData.Flags&0x80 != 0 {
		// The remaining bytes will contain the Extensions (this is optional and depends on implementation).
		if authenticatorData.AttestedCredential != nil {
			authenticatorData.Extensions = authenticatorData.AttestedCredential.PublicKey // Remaining bytes assumed extensions
		}
	}

	return authenticatorData, nil
}
