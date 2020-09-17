package portal

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"net"
	"regexp"
	"strings"
)

const usernameCharset = "0123456789abcdefghijklmnopqrstuvwxyz"

var emailAddrRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func validateUserInput(k, v string, opts map[string]interface{}) error {
	if v == "" {
		return fmt.Errorf("empty %s value", k)
	}
	switch k {
	case "handle":
		if err := validateUserInputHandle(v, opts); err != nil {
			return err
		}
	case "secret":
		if err := validateUserInputSecret(v, opts); err != nil {
			return err
		}
	case "email":
		if err := validateUserInputEmail(v, opts); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s validation is unsupported", k)
	}
	return nil
}

func validateUserInputHandle(v string, opts map[string]interface{}) error {
	if len(v) > 25 {
		return fmt.Errorf("the handle character length should not exceed 25 characters")
	}
	if err := utils.ContainsInvalidChars(usernameCharset, v); err != nil {
		return fmt.Errorf("the handle %s", err.Error())
	}
	return nil
}

func validateUserInputSecret(v string, opts map[string]interface{}) error {
	if len(v) > 255 {
		return fmt.Errorf("the handle character length should not exceed 255 characters")
	}
	return nil
}

func validateUserInputEmail(v string, opts map[string]interface{}) error {
	if len(v) < 3 && len(v) > 254 {
		return fmt.Errorf("the length of email address is invalid")
	}
	if !emailAddrRegex.MatchString(v) {
		return fmt.Errorf("the email address is invalid")
	}
	emailParts := strings.SplitN(v, "@", 2)
	if len(emailParts) != 2 {
		return fmt.Errorf("the email address is invalid")
	}
	if opts != nil {
		if enabled, exists := opts["check_domain_mx"]; exists {
			if enabled.(bool) {
				rr, err := net.LookupMX(emailParts[1])
				if err != nil {
					return fmt.Errorf("the email address domain is invalid")
				}
				if len(rr) < 1 {
					return fmt.Errorf("the email address domain is misconfigured")
				}
			}
		}
	}
	return nil
}
