package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/vmihailenco/msgpack/v5"
)

func TestUserExemptionsRevisionCommitsOnlyDecodedRoster(t *testing.T) {
	for _, format := range []string{"application/json", "application/x-msgpack"} {
		t.Run(format, func(t *testing.T) {
			revision, code, body := "7", http.StatusOK, `{"users":[{"id":7,"uuid":"user","dynamic_speed_exempt":true}]}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", format)
				w.Header().Set("ETag", "roster-seven")
				w.Header().Set("X-Dynamic-Speed-Exemptions-Revision", revision)
				w.WriteHeader(code)
				if code == http.StatusNotModified {
					return
				}
				if format == "application/x-msgpack" && body == "valid" {
					_ = msgpack.NewEncoder(w).Encode(UserListBody{Users: []UserInfo{{Id: 7, Uuid: "user", DynamicSpeedExempt: true}}})
				} else {
					_, _ = fmt.Fprint(w, body)
				}
			}))
			defer server.Close()
			if format == "application/x-msgpack" {
				body = "valid"
			}
			client := &Client{client: resty.New().SetBaseURL(server.URL)}
			users, err := client.GetUserList()
			if err != nil || len(users) != 1 || !users[0].DynamicSpeedExempt || client.UserExemptionsRevision() != 7 {
				t.Fatalf("valid roster not committed: %+v, %v", users, err)
			}
			revision, code = "8", http.StatusNotModified
			if users, err = client.GetUserList(); err != nil || users != nil || client.UserExemptionsRevision() != 7 {
				t.Fatalf("304 acknowledged an unseen roster: %+v %v", users, err)
			}
			code = http.StatusOK
			for _, malformed := range []string{`{"users":[{"id":7}]`, `{"users":null}`, `{}`, "\xc1"} {
				body = malformed
				if _, err = client.GetUserList(); err == nil || client.UserExemptionsRevision() != 7 || client.userEtag != "roster-seven" {
					t.Fatalf("invalid roster committed a revision: %q %v", body, err)
				}
			}
			for _, invalid := range []string{"-1", "invalid", "9223372036854775808"} {
				revision = invalid
				if _, err = client.GetUserList(); err == nil || client.UserExemptionsRevision() != 7 {
					t.Fatalf("invalid revision accepted: %s", revision)
				}
			}
			client.InvalidateUserListCache()
			if client.userEtag != "" || client.UserExemptionsRevision() != 7 {
				t.Fatal("retry did not clear only the roster cache")
			}
		})
	}
}

func TestGetUserListDistinguishesEmptyFromNotModified(t *testing.T) {
	for _, format := range []string{"application/json", "application/x-msgpack"} {
		t.Run(format, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 2 {
					if got := r.Header.Get("If-None-Match"); got != "empty-users" {
						t.Errorf("etag = %q", got)
					}
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("Content-Type", format)
				w.Header().Set("ETag", "empty-users")
				if format == "application/x-msgpack" {
					if err := msgpack.NewEncoder(w).Encode(UserListBody{Users: []UserInfo{}}); err != nil {
						t.Error(err)
					}
				} else {
					_, _ = w.Write([]byte(`{"users":[]}`))
				}
			}))
			defer server.Close()
			client := &Client{client: resty.New().SetBaseURL(server.URL)}
			users, err := client.GetUserList()
			if err != nil || users == nil || len(users) != 0 {
				t.Fatalf("empty users = %#v, err = %v", users, err)
			}
			unchanged, err := client.GetUserList()
			if err != nil || unchanged != nil {
				t.Fatalf("304 users = %#v, err = %v", unchanged, err)
			}
		})
	}
}
