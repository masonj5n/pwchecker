package pwchecker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckForPwnage(t *testing.T) {
	// Check Password "password" for pwnage, should return no error and pwned true
	pwd, err := CheckForPwnage("password")
	assert.Nil(t, err)
	assert.True(t, pwd.Pwnd)
	assert.NotEmpty(t, pwd.Pwd)

	// Check Password "", should return Passphrase Empty error
	pwd2, err := CheckForPwnage("")
	assert.Error(t, ErrPassphraseEmpty)
	assert.EqualValues(t, "", pwd2.Pwd)
	assert.EqualValues(t, "", pwd2.TmPwnd)
}
