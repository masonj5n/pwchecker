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

type Pwd struct {
	Pwnd   bool
	Pwd    string
	TmPwnd string
}

// CheckForPwnage takes passphrase as string, sends request to API and returns Pwd and error
func CheckForPwnage(pw string) (pwd *Pwd, err error) {
	if len(pw) < 1 {
		return pwd, ErrPassphraseEmpty
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
		return pwd, fmt.Errorf("HTTP request failed with error; %s", err)
	}
	defer response.Body.Close()
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return pwd, fmt.Errorf("HTTP request body read failed with error; %s", err)
	}
	resp := strings.Split((string(data)), "\n")
	for i := range resp {
		if sfx == resp[i][0:35] {
			reg := regexp.MustCompile("[^0-9]+")
			sanstrng := reg.ReplaceAllString(string(resp[i][36:]), "")
			return &Pwd{true, pw, sanstrng}, err
		}
	}

	return pwd, err
}
