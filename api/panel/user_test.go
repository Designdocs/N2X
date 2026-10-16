package panel

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/vmihailenco/msgpack/v5"
)

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
