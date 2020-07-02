package guerrilla

type LoginInfo struct {
	username string
	password string
	status   bool
}

type ValidateCallbackFunc func(username string, password string) (map[string]interface{}, error)

var Authentication = &AuthenticationValidator{
	handleFunctions: DefaultValidator,
}

type AuthenticationValidator struct {
	handleFunctions ValidateCallbackFunc
}

func DefaultValidator(username, password string) (map[string]interface{}, error) {
	return nil, nil
}

func (v *AuthenticationValidator) AddValidator(f ValidateCallbackFunc) {
	v.handleFunctions = f
}

func (v *AuthenticationValidator) Validate(a *LoginInfo) (map[string]interface{}, error) {
	return v.handleFunctions(a.username, a.password)
}
