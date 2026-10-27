package ddns

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Alibaba Cloud international accounts use the same global AliDNS RPC API.
const alidnsEndpoint = "https://alidns.aliyuncs.com/"

func aliEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func aliSignature(method string, params url.Values, secret string) string {
	canonical := strings.ReplaceAll(params.Encode(), "+", "%20")
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(method + "&%2F&" + aliEscape(canonical)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) alidns(ctx context.Context, action string, params url.Values, result any) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	params.Set("Action", action)
	params.Set("Version", "2015-01-09")
	params.Set("Format", "JSON")
	params.Set("AccessKeyId", s.config.DNSEnv["ALICLOUD_ACCESS_KEY"])
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", hex.EncodeToString(nonce))
	params.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	if token := s.config.DNSEnv["ALICLOUD_SECURITY_TOKEN"]; token != "" {
		params.Set("SecurityToken", token)
	}
	params.Set("Signature", aliSignature("POST", params, s.config.DNSEnv["ALICLOUD_SECRET_KEY"]))
	req, err := http.NewRequestWithContext(ctx, "POST", alidnsEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var body json.RawMessage
	if err := s.doJSON(req, &body); err != nil {
		return err
	}
	var status struct {
		Code      string
		RequestId string
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return err
	}
	if status.Code != "" {
		return fmt.Errorf("Alibaba Cloud DNS rejected DDNS request (%s)", status.Code)
	}
	if status.RequestId == "" {
		return errors.New("invalid Alibaba Cloud DNS response")
	}
	return json.Unmarshal(body, result)
}

func (s *Service) updateAliDNS(ctx context.Context, ip string) error {
	rr := "@"
	if s.config.Domain != s.config.ZoneName {
		rr = strings.TrimSuffix(s.config.Domain, "."+s.config.ZoneName)
	}
	var list struct {
		TotalCount    int
		DomainRecords struct {
			Record []struct {
				RecordId, RR, Type, Value, Line, Status string
				TTL                                     int
			}
		}
	}
	if err := s.alidns(ctx, "DescribeDomainRecords", url.Values{
		"DomainName": {s.config.ZoneName}, "RRKeyWord": {rr}, "TypeKeyWord": {s.config.RecordType},
		"SearchMode": {"EXACT"}, "PageSize": {"500"},
	}, &list); err != nil {
		return err
	}
	if list.TotalCount > 500 {
		return errors.New("too many Alibaba Cloud DNS records match the DDNS query")
	}
	var id, oldIP, line string
	ttl, matches := 0, 0
	for _, r := range list.DomainRecords.Record {
		if strings.EqualFold(r.RR, rr) && r.Type == s.config.RecordType {
			matches++
			id, oldIP, line, ttl = r.RecordId, r.Value, r.Line, r.TTL
			if r.Status != "ENABLE" {
				return errors.New("Alibaba Cloud DDNS record is disabled; enable it in the DNS console")
			}
		}
	}
	if matches > 1 {
		return errors.New("multiple Alibaba Cloud DDNS records match; keep a single A/AAAA record for this hostname")
	}
	params := url.Values{"RR": {rr}, "Type": {s.config.RecordType}, "Value": {ip}}
	action := "AddDomainRecord"
	if matches == 0 {
		params.Set("DomainName", s.config.ZoneName)
		params.Set("TTL", fmt.Sprint(s.config.TTL))
	} else {
		if id == "" {
			return errors.New("Alibaba Cloud DNS returned an empty record ID")
		}
		if sameIP(oldIP, ip) {
			return nil
		}
		action = "UpdateDomainRecord"
		params.Set("RecordId", id)
		if line != "" {
			params.Set("Line", line)
		}
		if ttl > 0 {
			params.Set("TTL", fmt.Sprint(ttl))
		}
	}
	var response struct{ RecordId string }
	if err := s.alidns(ctx, action, params, &response); err != nil {
		return err
	}
	if response.RecordId == "" {
		return errors.New("Alibaba Cloud DNS did not confirm the DDNS record")
	}
	return s.recordUpdated(ip, nil)
}
