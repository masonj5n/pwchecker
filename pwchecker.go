package pwchecker

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const pwnedURL = "https://api.pwnedpasswords.com/range/%s"


var (
	// ErrPassphraseEmpty indicates passphrase input was less than 1 character
	ErrPassphraseEmpty = errors.New("Passphrase Input Empty")
)

// Pwd is returned as a struct pointer when calling CheckForPwnage
type Pwd struct {
	Pwnd   bool   // Pwnd returns true if passphrase is found pwned via API
	Pwd    string // Pwd returns the passphrase string passed to the function
	TmPwnd string // TmPwnd returns the number of times the passphrase was found in the database
}

// CheckForPwnage takes passphrase as string, sends request to API and returns Pwd and error
func CheckForPwnage(pw string) (pwd *Pwd, err error) {
	// Check Passphrase not empty
	if len(pw) < 1 {
		return &Pwd{false, pw, ""}, ErrPassphraseEmpty
	}

	// Create SHA1 hash of passphrase
	hash := sha1.New()
	hash.Write([]byte((string(pw))))
	// Get Passphrase prefix
	pfx := strings.ToUpper(hex.EncodeToString(hash.Sum(nil))[0:5])
	sfx := strings.ToUpper(hex.EncodeToString(hash.Sum(nil))[5:])

	// Send request to pwnedpassword API
	response, err := http.Get(fmt.Sprintf(pwnedURL, pfx))
	if err != nil {
		return &Pwd{false, pw, ""}, fmt.Errorf("HTTP request failed with error; %s", err)
	}
	defer response.Body.Close()
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return &Pwd{false, pw, ""}, fmt.Errorf("HTTP request body read failed with error; %s", err)
	}
	// Check API Response
	resp := strings.Split((string(data)), "\n")
	// Check hash prefix against suffixes returned in API response
	for i := range resp {
		// if prefix and suffix match API response, return passphrase as pwned=true
		if sfx == resp[i][0:35] {
			reg := regexp.MustCompile("[^0-9]+")
			sanstrng := reg.ReplaceAllString(string(resp[i][36:]), "")
			return &Pwd{true, pw, sanstrng}, err
		}
	}

	return &Pwd{false, pw, ""}, err
}
