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

type ValidateCallbackFunc func(username string, password string) (map[string]interface{}, error)

var (
	Authentication = &AuthenticationValidator{
		handleFunctions: DefaultValidator,
	}
)

type AuthenticationValidator struct {
	handleFunctions ValidateCallbackFunc
}

func DefaultValidator(username, password string) (map[string]interface{},error) {
	return nil, nil
}

func (v *AuthenticationValidator) AddValidator(f ValidateCallbackFunc) {
	v.handleFunctions = f
}

func (v *AuthenticationValidator) Validate(a *LoginInfo) (map[string]interface{}, error) {
	return v.handleFunctions(a.username, a.password)
}
