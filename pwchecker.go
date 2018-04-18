package pwchecker

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const pwnedURL = "https://api.pwnedpasswords.com/range/%s"

type Pwd struct {
	Pwnd   bool
	Pwd    string
	TmPwnd string
}

func CheckForPwnage(pw string) (*Pwd, error) {

	hash := sha1.New()
	hash.Write([]byte((string(pw))))
	pfx := strings.ToUpper(hex.EncodeToString(hash.Sum(nil))[0:5])
	sfx := strings.ToUpper(hex.EncodeToString(hash.Sum(nil))[5:])

	response, err := http.Get(fmt.Sprintf(pwnedURL, pfx))
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return &Pwd{false, pw, ""}, err
	}

	data, _ := ioutil.ReadAll(response.Body)
	resp := strings.Split((string(data)), "\n")
	for i := range resp {
		if sfx == resp[i][0:35] {
			reg := regexp.MustCompile("[^0-9]+")
			sanstrng := reg.ReplaceAllString(string(resp[i][36:]), "")
			return &Pwd{true, pw, sanstrng}, nil
		}
	}

	return &Pwd{false, pw, ""}, nil
}
