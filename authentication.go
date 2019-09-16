package guerrilla

import (
	"bytes"
)

type authenticationCommand []byte

var (
	// Required the username
	cmdAuthUsername authenticationCommand = []byte("authUsername")
	// Required the password
	cmdAuthPassword authenticationCommand = []byte("authPassword")
)

func (c authenticationCommand) match(in []byte) bool {
	return bytes.Index(in, []byte(c)) == 0
}

type LoginInfo struct {
	username string
	password string
	status   bool
}

type ValidateCallbackFunc func(username string, password string) (orgID string, intputID string, err error)

var (
	Authentication = &AuthenticationValidator{}
)

type AuthenticationValidator struct {
	handleFunctions ValidateCallbackFunc
}

func (v *AuthenticationValidator) AddValidator(f ValidateCallbackFunc) {
	v.handleFunctions = f
}

func (v *AuthenticationValidator) Validate(a *LoginInfo) (string, string, error) {
	return v.handleFunctions(a.username, a.password)
}
