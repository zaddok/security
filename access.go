package security

import (
	"github.com/zaddok/log"
)

type AccessManager interface {
	Signup(host, first_name, last_name, email, password, ip string) (*[]string, string, error)
	GetSystemSession(host, firstname, lastname string) (Session, error)
	GetPersonByFirstNameLastName(site, firstname, lastname string) (Person, error)
	ActivateSignup(host, token, ip string) (string, string, error)
	ForgotPasswordRequest(host, email, ip string) (string, error)
	Authenticate(host, email, password, ip string) (Session, string, error)
	Session(host, cookie string) (Session, error)
	GuestSession(site string) Session
	Invalidate(host, cookie string) (Session, error)
	CreateSession(site string, uuid string, firstName string, lastName string, email string, ip string) (string, error)
	AddPerson(site, firstName, lastName, email string, password *string) (string, error)
	Log() log.Log
	Setting() Setting
	PicklistStore() PicklistStore
	GetRecentLogCollections(requestor Session) ([]LogCollection, error)
	GetLogCollection(uuid string, requestor Session) ([]LogEntry, error)
	WipeDatastore(namespace string) error
}

// Information about a verified user
type Person interface {
	GetUuid() string
	GetSite() string
	GetFirstName() string
	GetLastName() string
	GetEmail() string
}

// Encapsulates an as yet unverified request. i.e. Account creation.
type Verification interface {
	Token() string
	Data() string
}

// Contains information about a currently authenticated user session
type Session interface {
	GetPersonUuid() string
	GetToken() string
	GetSite() string
	GetFirstName() string
	GetLastName() string
	GetEmail() string
	IsAuthenticated() bool
}

type NewUserInfo struct {
	Site      string  `json:"site"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Email     string  `json:"email"`
	Password  *string `json:"password"`
}

const emailHtmlTemplates string = `
{{define "signup_confirmation_html"}}
<p>
Dear {{.FirstName}} {{.LastName}},
</p>

<p>
Thanks for signing up, please use the link below to confirm that your account
details are all correct.
</p>

<p>
<b>Name:</b> {{.FirstName}} {{.LastName}}<br/>
<b>Email:</b> {{.Email}}
<p>

<p>
<a href="{{.BaseURL}}/activate/{{.Token}}">{{.BaseURL}}/activate/{{.Token}}</a>
</p>

<p>
This URL will expire in 24 hours. If you don't want an account to be setup, feel
free to simply ignore this email.
</p>
{{end}}

{{define "signup_confirmation_text"}}
Dear {{.FirstName}} {{.LastName}}

Thanks for signing up, please use the link below to confirm that your account
details are all correct.

  Name: {{.FirstName}} {{.LastName}}
  Email: {{.Email}}

  {{.BaseURL}}/activate/{{.Token}}

This URL will expire in 24 hours. If you don't want an account to be setup, feel
free to simply ignore this email.
{{end}}

{{define "lost_password_html"}}
<p>
Dear {{.FirstName}} {{.LastName}},
</p>

<p>
We received a request to reset the password for your account, if this request
was initiated by you, then you can go ahead and reset your password at the
link below. This link will expire in 24 hours.
</p>

<p>
<b>Name:</b> {{.FirstName}} {{.LastName}}<br/>
<b>Email:</b> {{.Email}}
<p>

<p>
<a href="{{.BaseURL}}/reset/{{.Token}}">{{.BaseURL}}/reset/{{.Token}}</a>
</p>

<p>
If you did not initiate this password reset request, no action is required,
simply ignore this email.
</p>
{{end}}

{{define "lost_password_text"}}
Dear {{.FirstName}} {{.LastName}}

We received a request to reset the password for your account, if this request
was initiated by you, then you can go ahead and reset your password at the
link below. This link will expire in 24 hours.

  Name: {{.FirstName}} {{.LastName}}
  Email: {{.Email}}

  {{.BaseURL}}/reset/{{.Token}}

If you did not initiate this password reset request, no action is required,
simply ignore this email.
{{end}}
`

var SecurityHeader = `
{{define "security_header"}}
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<meta charset="utf-8">
		<meta property="og:site_name" content="{{.SiteName}}"/>
		<meta name="apple-mobile-web-app-title" content="{{.SiteName}}">
		<meta name="apple-mobile-web-app-capable" content="yes">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=1.0, minimum-scale=1.0, maximum-scale=1.0">
		<title>Signup &mdash; {{.SiteName}}</title>
		<link rel="stylesheet" type="text/css" href="/style.css" />
		<style type="text/css">
			@font-face {
				font-family: 'FontAwesomeSolid';
				src: url('/font/fa-solid-900.eot');
				src: url('/font/fa-solid-900.eot?#iefix')
				format('embedded-opentype'), url('/font/fa-solid-900.woff')
				format('woff'), url('/font/fa-solid-900.ttf') format('truetype');
				font-weight: normal;
				font-style: normal
			}
		body {
			margin-left: auto;
			margin-right: auto;
			max-width: 30em;
			background: #fafafa;
		}
		form {
			padding: 0;
			margin: 0;
		}
		#signin_box input[type=text],
		#signup_box input[type=text] {
			margin-bottom: 0.4em;
			font-size: 1em;
			border: 1px solid #e8e8e8;
			width: 100%;
			padding: 0.56em;
			background: #fcfcfc;
		}
		input[type=submit] {
			background: #3898f8;
			border: 0px;
			padding: 0.6em;
			border-radius: 0.35em;
			-webkit-border-radius: 0.35em;
			-moz-border-radius: 0.35em;
			color: white;
			font-weight: bold;
			width: 100%;
			margin-top: 0.15em;
		}
		#signin_box input[type=password],
		#signup_box input[type=password] {
			margin-bottom: 0.4em;
			font-size: 1em;
			border: 1px solid #e8e8e8;
			width: 100%;
			padding: 0.56em;
			background: #fcfcfc;
		}
		#signin_box h2 {
			text-align: center;
			margin-top: 0.4em;
			margin-bottom: 0.6em;
		}
		#signin_box h3,
		#signup_box h3 {
			margin-top: 0;
			margin-bottom: 0.2em;
		}
		#signin_box p,
		#signup_box p {
			margin-top: 0.2em;
			margin-bottom: 0.4em;
			padding: 0;
		}
		#signin_box {
			margin-top: 2em;
		}
		#signin_box,
		#signup_box {
			margin-bottom: 1.5em;
			padding: 1em 2.5em 1em 2.5em;
			border: 1px solid #e6e6e6;
			background: #fff;
		}

		div.error { border: 1px solid #C99; background: #FCC; color: #633; }
		div.info { border: 1px solid #bbe; background: #ddf; color: #558; }
		div.success { border: 1px solid #aFcA80; color: #4F8A10; background-color: #DFF2BF; }
		div.warning { border: 1px solid #e4e4c8; color: #aa2; background-color: #ffffd0; }
		div.error, div.info, div.success, div.warning { padding: 0.4em 1em 0.3em 0.7em; margin-bottom: 1em; clear: both; }
		div.error::before { font-family: FontAwesomeSolid; content: "\f057\00a0\00a0"; opacity: 0.7; float: left; color: #633; padding-top: 0.03em; }
		div.info:before { font-family: FontAwesomeSolid; content: "\f05a\00a0\00a0"; opacity: 0.5; float: left; color: #336; padding-top: 0.1em; }
		div.success::before { font-family: FontAwesomeSolid; content: "\f00c\00a0\00a0"; opacity: 0.7; float: left; color: #4F8A10; padding-top: 0.1em; }
		div.warning::before { font-family: FontAwesomeSolid; content: "\f071\00a0\00a0"; opacity: 0.5; float: left; color: #aa2; padding-top: 0.1em; }
		.error ul,
		.warning ul { padding: 0 0 0 2em; margin: 0; }
		.error p,
		.success p,
		.warning p,
		.info p { padding: 0 0 0 1.6em; margin: 0; }
		.error ul li,
		.success ul li,
		.warning ul li,
		.info ul li { padding: 0; margin: 0; list-style-type: none; }
	</style>
</head>
<body class="signin">
{{end}}


{{define "security_footer"}}
</body></html>
{{end}}
`

var SignupTemplate = `
{{define "signin_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.SiteName}}</h2>
</div>

<form method="post" action="/signin" id="signin">
<input type="hidden" name="referer" value="{{.Referer}}">
<h3>Sign in</h3>

<label for="signin_username">
<input type="text" name="signin_email" id="signin_email" value='{{.SigninEmail}}' placeholder="Email address"/>
</label>

<label for="signin_password">
<input type="password" name="signin_password" id="signin_password" value="{{.Password}}" placeholder="Password"/></span>
	<input type="submit" name="signin" value="Sign in"/>
</label>


<p><a href="/forgot/">Forgot your password?</a></p>

</form>


</div>

{{if .AllowSignup}}
<div id="signup_box">

<form method="post" action="/signup" id="signup">
<h3>Sign up</h3>

<label for="firstname">
<input type="text" placeholder="First name" name="first_name" id="first_name" value='{{.FirstName}}'/>
</label>

<label for="lastname">
<input type="text" placeholder="Last name" name="last_name" id="last_name" value='{{.LastName}}'/>
</label>

<label for="email">
<input type="text" placeholder="Email address" name="email" id="email" value='{{.Email}}'/>
</label>

<label for="password">
<input type="password" placeholder="Password" name="password" id="password" autocomplete="off" value="{{.Password}}"/>
</label>

<label for="password2">
<input type="password" placeholder="Re-type password" name="password2" id="password2" value="{{.Password2}}"/>
</label>

<p>By signing up, you agree that you have read and accepted our <a href="/user.agreement">User Agreement</a>, you consent to our <a href="/privacy">Privacy Notice</a> and receiving email that may contain marketing communications from us.</p>

<div class="submit">
<input type="submit" name="signup" value="Sign up"/>
 </div>

</form>
</div>
{{end}}

<script type="text/javascript">
if(document.getElementById('signin_email').value!="") {
	 document.getElementById('signin_password').focus();
} else {
	document.getElementById('signin_email').focus();
}
</script>

{{template "security_footer" .}}
{{end}}
`

var ForgotTemplate = `
{{define "forgot_password_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.SiteName}}</h2>
</div>

<form method="post" action="/forgot/" id="forgot">
<h3>Forgot Password</h3>

<label for="signin_username">
<input type="text" name="signin_email" id="forgot_email" value='{{.SigninEmail}}' placeholder="Email address"/>
</label>

<p>Request an email that contains a password reset link.</p>

<label for="signin_reset">
	<input type="submit" name="signin_reset" value="Reset Password"/>
</label>

</form>

<script type="text/javascript">
	document.getElementById('forgot_email').focus();
</script>

</div>
{{template "security_footer" .}}
{{end}}
`

var ActivateTemplate = `
{{define "activate_account_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.SiteName}}</h2>
</div>

<form method="post" action="/signin" id="signin">
<h3>Sign in</h3>

<label for="signin_username">
<input type="text" name="signin_email" id="signin_email" value='{{.SigninEmail}}' placeholder="Email address"/>
</label>

<label for="signin_password">
<input type="password" name="signin_password" id="signin_password" value="{{.Password}}" placeholder="Password"/></span>
	<input type="submit" name="signin" value="Sign in"/>
</label>


<p><a href="/forgot/">Forgot your password?</a></p>

</form>


</div>
{{template "security_footer" .}}
{{end}}
`
