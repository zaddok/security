package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/rand"
	"net/smtp"
	"strings"
	"syscall"
	"time"
)

var seeded = false

func RandomString(size int) string {
	if !seeded {
		seeded = true
		rand.Seed(time.Now().UTC().UnixNano())
	}
	bytes := make([]byte, size)
	for i := 0; i < size; i++ {
		b := uint8(rand.Int31n(36))
		if b < 26 {
			bytes[i] = 'A' + b
		} else if b < 52 {
			bytes[i] = 'a' + (b - 26)
		} else {
			bytes[i] = '0' + (b - 52)
		}
	}
	return string(bytes)
}

func HashPassword(password string) *string {
	if password == "" {
		return nil
	}

	seed := RandomString(16)

	var h hash.Hash = sha256.New()
	h.Write([]byte(seed))
	h.Write([]byte(password))
	b := base64.StdEncoding.EncodeToString(h.Sum(nil))

	p := fmt.Sprintf("%s:%s", seed, b)
	return &p
}

func VerifyPassword(actualPassword string, password string) bool {
	if actualPassword == "" || password == "" {
		return false
	}

	part := strings.Split(actualPassword, ":")
	if len(part) != 2 {
		return false
	}

	var h hash.Hash = sha256.New()
	h.Write([]byte(part[0]))
	h.Write([]byte(password))
	b := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return b == part[1]
}

func NowMilliseconds() int64 {
	var tv syscall.Timeval
	syscall.Gettimeofday(&tv)
	return int64(tv.Sec)*1e3 + int64(tv.Usec)/1e3
}

// PasswordStrength checks the provide password meets a minimum security level. Warnings
// about weaknesses are returned as plain English strings.
func PasswordStrength(password string) []string {
	messages := []string{}

	hasLetter := false
	hasNumber := false
	hasPunctuation := false
	hasRepeatedCharacter := false

	var lastRune rune
	var lastRuneCount int = 0
	for _, c := range password {
		if c != lastRune {
			lastRune = c
			lastRuneCount = 0
		} else {
			lastRuneCount = lastRuneCount + 1
			if lastRuneCount >= 2 {
				hasRepeatedCharacter = true
			}
		}
		if c > '0' && c < '9' {
			hasNumber = true
		}
		if c > 'A' && c < 'Z' {
			hasLetter = true
		}
		if c > 'a' && c < 'z' {
			hasLetter = true
		}
		if c == ' ' || c == '.' || c == ',' ||
			c == '=' || c == '!' || c == '@' ||
			c == '#' || c == '$' || c == '%' ||
			c == '^' || c == ':' || c == '&' ||
			c == '*' || c == '(' || c == ')' ||
			c == '-' || c == '_' || c == '+' ||
			c == '[' || c == ']' || c == '{' ||
			c == '}' || c == '|' || c == '\\' ||
			c == '/' || c == '\'' || c == '"' ||
			c == '`' || c == '~' || c == '<' ||
			c == '>' || c == ';' || c == '?' {
			hasPunctuation = true
		}
	}

	if len(password) < 8 {
		messages = append(messages, "Passwords must be at least 8 characters")
	}

	if len(password) < 12 {
		if !hasLetter || !hasNumber || !hasPunctuation {
			messages = append(messages, "Passwords less than 10 characters must contain letters, numbers, and punctuation")
		}
	}

	if hasRepeatedCharacter {
		messages = append(messages, "Passwords may not have repeated characters, i.e. 111")
	}

	if strings.Index(password, "abc") >= 0 {
		messages = append(messages, "Password may not contain 'abc'")
	}

	if strings.Index(password, "123") >= 0 {
		messages = append(messages, "Password may not contain '123'")
	}

	return messages
}

func Underscorify(text string) string {
	text = strings.ToLower(text)
	text = strings.Replace(text, " ", "_", -1)
	text = strings.Replace(text, "-", "_", -1)
	text = strings.Replace(text, "'", "", -1)
	text = strings.Replace(text, "?", "", -1)
	text = strings.Replace(text, ":", "", -1)
	return text
}

// MatchingDate checks if two dates are equal, were one or both may be nil. Two dates
// are considered to match if both dates are nil, or both have the same number of seconds
// since 1970
func MatchingDate(a, b *time.Time) bool {
	if a != nil && b == nil {
		return false
	}
	if b != nil && a == nil {
		return false
	}
	if a == nil && b == nil {
		return true
	}
	if a.Unix() != b.Unix() {
		return false
	}
	return true
}

// SendEmail delivers an email message over smtp to the intended target using the preconfigured
// smtp settings. Returns with a list of strings to present to the user if sending fails, or an
// error object if a system error has occured.
func SendEmail(am AccessManager, site, subject, toEmail, toName string, textContent, htmlContent []byte) (*[]string, error) {
	return SendEmailWithAttachment(am, site, subject, toEmail, toName, textContent, htmlContent, "", "", nil)
}

// SendEmail delivers an email message over smtp to the intended target using the preconfigured
// smtp settings. Returns with a list of strings to present to the user if sending fails, or an
// error object if a system error has occured.
func SendEmailWithAttachment(am AccessManager, site, subject, toEmail, toName string, textContent, htmlContent []byte, attachmentName, attachmentType string, attachment []byte) (*[]string, error) {
	var results []string

	smtpHostname := am.Setting().GetWithDefault(site, "smtp.hostname", "")
	smtpPassword := am.Setting().GetWithDefault(site, "smtp.password", "")
	smtpPort := am.Setting().GetWithDefault(site, "smtp.port", "")
	smtpUser := am.Setting().GetWithDefault(site, "smtp.user", "")
	supportName := am.Setting().GetWithDefault(site, "support_team.name", "")
	supportEmail := am.Setting().GetWithDefault(site, "support_team.email", "")

	if smtpHostname == "" {
		results = append(results, "Missing \"smtp.hostname\" host, setting, cant send message notification")
	}
	if smtpPort == "" {
		results = append(results, "Missing \"smtp.port\" setting, cant send message notification")
	}
	if supportName == "" {
		results = append(results, "Missing \"support_team.name\" setting, cant send message notification")
	}
	if supportEmail == "" {
		results = append(results, "Missing \"support_team.email\" setting, cant send message notification")
	}

	if len(results) > 0 {
		am.Log().Error("Email configuration issue. Not sending email to: %s Subject: %s ", toEmail, subject)
		am.Log().Warning("Check configuration: %s", results[0])
		return &results, errors.New(results[0])
	}

	var w bytes.Buffer
	boundary := RandomString(20)
	w.Write([]byte("Subject: "))
	w.Write([]byte(subject))
	w.Write([]byte("\r\n"))
	w.Write([]byte(fmt.Sprintf("From: %s <%s>\r\n", supportName, supportEmail)))
	w.Write([]byte(fmt.Sprintf("To: %s <%s>\r\n", toName, toEmail)))
	w.Write([]byte("Content-transfer-encoding: 8BIT\r\n"))
	w.Write([]byte("MIME-version: 1.0\r\n"))
	w.Write([]byte("Content-type: multipart/alternative; charset=\"UTF-8\"; boundary="))
	w.Write([]byte(boundary))
	w.Write([]byte("\r\n\r\n"))
	w.Write([]byte(fmt.Sprintf("--%s\r\n", boundary)))
	w.Write([]byte("Content-Type: text/plain; charset=\"UTF-8\"; format=\"flowed\"\r\n"))
	w.Write([]byte("Content-Transfer-Encoding: 8bit\r\n\r\n"))
	//w.Write([]byte("Content-Disposition: inline\r\n"))
	w.Write(textContent)

	w.Write([]byte(fmt.Sprintf("\r\n\r\n--%s\r\n", boundary)))
	w.Write([]byte("Content-Type: text/html; charset=\"UTF-8\"\r\n"))
	w.Write([]byte("Content-Transfer-Encoding: base64\r\n\r\n"))
	w.Write([]byte(base64.StdEncoding.EncodeToString(htmlContent)))

	if attachmentName != "" && attachmentType != "" && len(attachment) > 0 {
		w.Write([]byte(fmt.Sprintf("\r\n\r\n--%s\r\n", boundary)))
		w.Write([]byte("Content-Type: " + attachmentType + "; charset=\"UTF-8\"\r\n"))
		w.Write([]byte("Content-Transfer-Encoding: base64\r\n"))
		w.Write([]byte("Content-Disposition: attachment; filename=\"" + attachmentName + "\"\r\n\r\n"))
		w.Write([]byte(base64.StdEncoding.EncodeToString(attachment)))
	}

	w.Write([]byte(fmt.Sprintf("\r\n\r\n--%s--\r\n", boundary)))

	var auth smtp.Auth
	if smtpUser != "" && smtpPassword != "" {
		auth = smtp.PlainAuth("", smtpUser, smtpPassword, smtpHostname)
	}
	err := smtp.SendMail(fmt.Sprintf("%s:%s", smtpHostname, smtpPort), auth, supportEmail, []string{toEmail}, w.Bytes())
	if err != nil {
		am.Log().Error("Email delivery failed. To: %s Subject: %s Error: %v", toName, subject, err)
		results = append(results, "Email delivery failed. Please retry shortly.")
		return &results, errors.New(results[0])
	} else {
		am.Log().Info("Email delivered. To: %s Subject: %s ", toEmail, subject)
	}

	return &results, nil
}
