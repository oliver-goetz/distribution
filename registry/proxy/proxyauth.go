package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/distribution/distribution/v3/internal/client/auth"
	"github.com/distribution/distribution/v3/internal/client/auth/challenge"
	"github.com/distribution/distribution/v3/internal/dcontext"
)

const challengeHeader = "Docker-Distribution-Api-Version"

type basicAuth struct {
	username string
	password string
}

func (b basicAuth) Basic(u *url.URL) (string, string) {
	return b.username, b.password
}

func (b basicAuth) RefreshToken(u *url.URL, service string) string {
	return ""
}

func (b basicAuth) SetRefreshToken(u *url.URL, service, token string) {
}

type credentials struct {
	creds map[string]basicAuth
}

func (c credentials) Basic(u *url.URL) (string, string) {
	return c.creds[u.String()].Basic(u)
}

func (c credentials) RefreshToken(u *url.URL, service string) string {
	return ""
}

func (c credentials) SetRefreshToken(u *url.URL, service, token string) {
}

// configureAuth stores credentials for challenge responses
func configureAuth(username, password, remoteURL string) (auth.CredentialStore, auth.CredentialStore, error) {
	creds := map[string]basicAuth{}

	authURLs, err := getAuthURLs(remoteURL)
	if err != nil {
		return nil, nil, err
	}

	for _, url := range authURLs {
		dcontext.GetLogger(dcontext.Background()).Infof("Discovered token authentication URL: %s", url)
		creds[url] = basicAuth{
			username: username,
			password: password,
		}
	}

	bs := basicAuth{username: username, password: password}

	return credentials{creds: creds}, bs, nil
}

func getAuthURLs(remoteURL string) ([]string, error) {
	authURLs := []string{}

	resp, err := http.Get(remoteURL + "/v2/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	for _, c := range challenge.ResponseChallenges(resp) {
		if strings.EqualFold(c.Scheme, "bearer") {
			authURLs = append(authURLs, c.Parameters["realm"])
		}
	}

	return authURLs, nil
}

func ping(manager challenge.Manager, endpoint, versionHeader string) error {
	resp, err := http.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return manager.AddResponse(resp)
}
