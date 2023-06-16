package utils

import "regexp"

func ValidateSerial(serial string) bool {
	regexPattern := `^\d{18}$`
	regex := regexp.MustCompile(regexPattern)
	return regex.MatchString(serial)
}
