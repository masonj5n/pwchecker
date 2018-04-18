package passwordChecker

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

func CheckForPwnage(passwd string) (bool, string, string) {

	passHash := sha1.New()
	passHash.Write([]byte((string(passwd))))
	hashSuffix := strings.ToUpper(hex.EncodeToString(passHash.Sum(nil))[5:])
	firstFive := hex.EncodeToString(passHash.Sum(nil))[0:5]

	response, err := http.Get("https://api.pwnedpasswords.com/range/" + firstFive)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response.Body)
		responseSlice := strings.Split((string(data)), "\n")
		for i := range responseSlice {
			if hashSuffix == responseSlice[i][0:35] {
				reg, err := regexp.Compile("[^0-9]+")
				if err != nil {
					fmt.Printf("Regular expression error")
				}
				sanitizedString := reg.ReplaceAllString(string(responseSlice[i][36:]), "")
				return true, passwd, sanitizedString
			}
		}
	}
	return false, passwd, ""
}
