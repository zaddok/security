package security

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type MoodleAuthenticationHandler struct {
	MoodleUrl string
}

// CheckMoodlePassword completes the moodle signin form and checks the response from moodle for indicators of signin success or failure.
func (m *MoodleAuthenticationHandler) Authenticate(username, password string) (bool, error) {

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	req, _ := http.NewRequest("GET", m.MoodleUrl, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		//fmt.Printf("unalble to fetch login page. Http status: '%s'\n", resp.StatusCode)
		return false, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	b := string(body)
	i := strings.Index(b, `name="logintoken" value="`)
	if i <= 0 {
		return false, errors.New("Moodle signin form data missing. Check moodle version compatibility.")
	}
	logintoken := b[i+25 : i+57]
	formData := url.Values{
		"logintoken": {logintoken},
		"username":   {username},
		"password":   {password},
	}

	req, _ = http.NewRequest("POST", m.MoodleUrl, strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		return false, err
	}
	body, err = ioutil.ReadAll(resp.Body)
	b = string(body)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == 200 && strings.Index(b, "<title>Dashboard</title>") > 0 {
		return true, nil
	}
	if strings.Index(b, "Invalid login, please try again") > 0 {
		return false, nil
	}

	return false, errors.New("Unrecognised moodle response. Check moodle version compatibility")
}
