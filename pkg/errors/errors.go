package errors

import (
	"errors"
)

var (
	ErrUnexpectedAuthenticatorResponseType = errors.New("unexpected authenticator response type")
)
