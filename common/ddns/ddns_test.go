package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Designdocs/N2X/conf"
	openapiutil "github.com/alibabacloud-go/openapi-util/service"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func mockService(t *testing.T, provider string, fn roundTripFunc) *Service {
	t.Helper()
	c := conf.DDNSConfig{Enabled: true, Provider: provider, Domain: "edge.example.com", DNSEnv: map[string]string{
		"CF_DNS_API_TOKEN": "scoped-token", "ALICLOUD_ACCESS_KEY": "ram-key", "ALICLOUD_SECRET_KEY": "ram-secret",
	}}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.client = &http.Client{Transport: fn}
	s.ipClient = s.client
	return s
}

func TestCloudflareDDNSCreateUpdateAndNoop(t *testing.T) {
	for _, scenario := range []string{"missing", "changed", "same", "duplicates"} {
		t.Run(scenario, func(t *testing.T) {
			writes := 0
			s := mockService(t, "cloudflare", func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "api.ipify.org" {
					return reply("1.2.3.4\n"), nil
				}
				if r.Header.Get("Authorization") != "Bearer scoped-token" {
					t.Error("missing token authentication")
				}
				if r.URL.Path == "/client/v4/zones" {
					if r.URL.Query().Get("name") != "example.com" {
						t.Error("wrong zone lookup")
					}
					return reply(`{"success":true,"result":[{"id":"zone","name":"example.com"}]}`), nil
				}
				if r.Method == "GET" {
					if r.URL.Query().Get("name") != "edge.example.com" || r.URL.Query().Get("type") != "A" {
						t.Error("wrong record filter")
					}
					records := `[]`
					if scenario != "missing" {
						ip := "5.6.7.8"
						if scenario == "same" {
							ip = "1.2.3.4"
						}
						record := fmt.Sprintf(`{"id":"record","name":"edge.example.com","type":"A","content":%q}`, ip)
						records = "[" + record + "]"
						if scenario == "duplicates" {
							records = "[" + record + "," + record + "]"
						}
					}
					return reply(`{"success":true,"result":` + records + `}`), nil
				}
				writes++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if scenario == "missing" {
					if r.Method != "POST" || body["proxied"] != false || body["ttl"] != float64(600) || body["type"] != "A" {
						t.Error("wrong create request")
					}
				} else {
					if r.Method != "PATCH" || r.URL.Path != "/client/v4/zones/zone/dns_records/record" || len(body) != 1 {
						t.Error("update must preserve existing record metadata")
					}
				}
				if body["content"] != "1.2.3.4" {
					t.Error("wrong new address")
				}
				return reply(`{"success":true,"result":{}}`), nil
			})
			err := s.Update(context.Background())
			if scenario == "duplicates" {
				if err == nil || writes != 0 {
					t.Fatal("ambiguous records must not be modified")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if scenario == "same" {
				want = 0
			}
			if writes != want {
				t.Fatalf("writes=%d, want %d", writes, want)
			}
		})
	}
}

func TestDDNSInvalidIPNeverTouchesProvider(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "100.64.1.1", "not an IP", "2001:4860:4860::8888", "::ffff:100.64.1.1"} {
		t.Run(ip, func(t *testing.T) {
			s := mockService(t, "cloudflare", func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "api.ipify.org" {
					t.Fatal("provider called with invalid IP")
				}
				return reply(ip), nil
			})
			if err := s.Update(context.Background()); err == nil {
				t.Fatal("invalid or mismatched IP accepted")
			}
		})
	}
}

func TestDDNSIPv6AndDisabled(t *testing.T) {
	calls := 0
	s := mockService(t, "cloudflare", func(r *http.Request) (*http.Response, error) { calls++; return reply("2001:4860:4860::8888"), nil })
	s.config.Enabled = false
	if err := s.Update(context.Background()); err != nil || calls != 0 {
		t.Fatal("disabled DDNS performed network I/O")
	}
	s.config.Enabled = true
	s.config.RecordType = "AAAA"
	s.config.IPURL = "https://api6.ipify.org"
	ip, err := s.detectIP(context.Background())
	if err != nil || ip != "2001:4860:4860::8888" {
		t.Fatalf("IPv6 detection failed: %v", err)
	}
}

func TestAliSignatureMatchesSDKVector(t *testing.T) {
	// Alibaba Cloud openapi-util/service/service_test.go Test_GetRPCSignature.
	if got := aliSignature("", url.Values{"test": {"ok"}}, "accessKeySecret"); got != "jHx/oHoHNrbVfhncHEvPdHXZwHU=" {
		t.Fatalf("signature=%s", got)
	}
	for _, method := range []string{"GET", "POST"} {
		params := url.Values{"AccessKeyId": {"testid"}, "Action": {"DescribeDomainRecords"},
			"RRKeyWord": {"space + ~ 中文"}, "Timestamp": {"2026-10-26T12:00:00Z"}}
		signed := map[string]*string{}
		for k := range params {
			value := params.Get(k)
			signed[k] = &value
		}
		secret := "testsecret"
		want := *openapiutil.GetRPCSignature(signed, &method, &secret)
		if got := aliSignature(method, params, secret); got != want {
			t.Fatalf("%s signature differs from official SDK", method)
		}
	}
}

func TestAliDNSInternationalCreateUpdateAndNoop(t *testing.T) {
	for _, scenario := range []string{"missing", "changed", "same", "duplicates", "disabled", "apex"} {
		t.Run(scenario, func(t *testing.T) {
			writes := 0
			rr := "edge"
			if scenario == "apex" {
				rr = "@"
			}
			s := mockService(t, "alidns", func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "api.ipify.org" {
					return reply("1.2.3.4"), nil
				}
				if r.URL.Host != "alidns.aliyuncs.com" || r.Method != "POST" || r.URL.RawQuery != "" {
					t.Error("wrong international DNS API request")
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				p := r.PostForm
				if p.Get("AccessKeyId") != "ram-key" || p.Get("Signature") == "" || p.Get("Version") != "2015-01-09" {
					t.Error("missing signed API credentials")
				}
				if p.Get("Action") == "DescribeDomainRecords" {
					if p.Get("DomainName") != "example.com" || p.Get("RRKeyWord") != rr || p.Get("SearchMode") != "EXACT" {
						t.Error("wrong exact record query")
					}
					records := `[]`
					total := 0
					if scenario != "missing" {
						ip := "5.6.7.8"
						if scenario == "same" {
							ip = "1.2.3.4"
						}
						status := "ENABLE"
						if scenario == "disabled" {
							status = "DISABLE"
						}
						record := fmt.Sprintf(`{"RecordId":"rid","RR":%q,"Type":"A","Value":%q,"Line":"telecom","TTL":1200,"Status":%q}`, rr, ip, status)
						records = "[" + record + "]"
						total = 1
						if scenario == "duplicates" {
							records = "[" + record + "," + record + "]"
							total = 2
						}
					}
					return reply(fmt.Sprintf(`{"RequestId":"req","TotalCount":%d,"DomainRecords":{"Record":%s}}`, total, records)), nil
				}
				writes++
				if p.Get("Value") != "1.2.3.4" || p.Get("RR") != rr || p.Get("Type") != "A" {
					t.Error("wrong record write")
				}
				if scenario == "missing" {
					if p.Get("Action") != "AddDomainRecord" || p.Get("DomainName") != "example.com" || p.Get("TTL") != "600" {
						t.Error("wrong creation")
					}
				} else {
					if p.Get("Action") != "UpdateDomainRecord" || p.Get("RecordId") != "rid" || p.Get("Line") != "telecom" || p.Get("TTL") != "1200" {
						t.Error("existing metadata was not preserved")
					}
				}
				return reply(`{"RequestId":"req","RecordId":"rid"}`), nil
			})
			if scenario == "apex" {
				s.config.Domain = "example.com"
			}
			err := s.Update(context.Background())
			if scenario == "duplicates" || scenario == "disabled" {
				if err == nil || writes != 0 {
					t.Fatal("ambiguous/disabled record must not be modified")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if scenario == "same" {
				want = 0
			}
			if writes != want {
				t.Fatalf("writes=%d want=%d", writes, want)
			}
		})
	}
}

func TestDDNSFailureCanRetryAndErrorsRedactCredentials(t *testing.T) {
	fail := true
	s := mockService(t, "alidns", func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.ipify.org" {
			return reply("1.2.3.4"), nil
		}
		if fail {
			return reply(`{"RequestId":"r","Code":"ram-secret"}`), nil
		}
		return reply(`{"RequestId":"r","DomainRecords":{"Record":[{"RecordId":"r","RR":"edge","Type":"A","Value":"1.2.3.4","Status":"ENABLE"}]}}`), nil
	})
	err := s.Update(context.Background())
	if err == nil || strings.Contains(err.Error(), "ram-secret") {
		t.Fatalf("missing error or leaked credentials: %v", err)
	}
	fail = false
	if err := s.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDDNSIPv6DoesNotRewriteEquivalentRecord(t *testing.T) {
	s := mockService(t, "cloudflare", func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api6.ipify.org" {
			return reply("2001:4860:4860::8888"), nil
		}
		if r.URL.Path == "/client/v4/zones" {
			return reply(`{"success":true,"result":[{"id":"zone","name":"example.com"}]}`), nil
		}
		if r.Method != "GET" {
			t.Fatal("unchanged IPv6 address was rewritten")
		}
		if r.URL.Query().Get("type") != "AAAA" {
			t.Fatal("wrong IPv6 record type")
		}
		return reply(`{"success":true,"result":[{"id":"record","name":"edge.example.com","type":"AAAA","content":"2001:4860:4860:0000:0000:0000:0000:8888"}]}`), nil
	})
	s.config.RecordType = "AAAA"
	s.config.IPURL = "https://api6.ipify.org"
	if err := s.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDDNSCancelsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	s := mockService(t, "cloudflare", func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Update(ctx) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled DDNS request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight DDNS request ignored shutdown")
	}
}
