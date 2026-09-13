package panel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
)

// tokenParam matches the panel API key New puts in every request URL, which
// net/http repeats in its errors and some panels echo in error bodies.
var tokenParam = regexp.MustCompile(`token=[^&"\s]+`)

// RedactToken masks the panel API key query parameter in s.
func RedactToken(s string) string {
	return tokenParam.ReplaceAllString(s, "token=[REDACTED]")
}

// redactingLogger replaces resty's default stderr logger, whose retry
// warnings print the full request URL, and sends its lines to logrus.
type redactingLogger struct{}

func (redactingLogger) Errorf(format string, v ...interface{}) {
	logrus.Error(RedactToken(fmt.Sprintf(format, v...)))
}

func (redactingLogger) Warnf(format string, v ...interface{}) {
	logrus.Warn(RedactToken(fmt.Sprintf(format, v...)))
}

func (redactingLogger) Debugf(format string, v ...interface{}) {
	logrus.Debug(RedactToken(fmt.Sprintf(format, v...)))
}

// Debug set the client debug for client
func (c *Client) Debug() {
	c.client.SetDebug(true)
}

// assembleURL returns the URL a request to path goes to, for error messages.
// path.Join cannot be used here: it collapses the "//" after the scheme.
func (c *Client) assembleURL(path string) string {
	return strings.TrimRight(c.APIHost, "/") + path
}

// checkResponse turns a failed request into an error with the panel API key
// masked. The transport error is flattened into the message rather than
// wrapped, so nothing up the chain can print the unmasked URL.
func (c *Client) checkResponse(res *resty.Response, path string, err error) error {
	if err != nil {
		return redactedErrorf("request %s failed: %s", c.assembleURL(path), err)
	}
	if res == nil {
		return redactedErrorf("request %s failed: empty response", c.assembleURL(path))
	}
	if res.StatusCode() >= 400 {
		body := res.Body()
		return redactedErrorf("request %s failed: %s", c.assembleURL(path), string(body))
	}
	return nil
}

func redactedErrorf(format string, v ...interface{}) error {
	return errors.New(RedactToken(fmt.Sprintf(format, v...)))
}
