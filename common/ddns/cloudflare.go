package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const cloudflareEndpoint = "https://api.cloudflare.com/client/v4"

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

func (s *Service) cloudflare(ctx context.Context, method, path string, body any, result any) error {
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareEndpoint+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.DNSEnv["CF_DNS_API_TOKEN"])
	req.Header.Set("Content-Type", "application/json")
	envelope := struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Code int `json:"code"`
		} `json:"errors"`
	}{}
	if err := s.doJSON(req, &envelope); err != nil {
		return err
	}
	if !envelope.Success {
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("Cloudflare API rejected DDNS request (code %d)", envelope.Errors[0].Code)
		}
		return errors.New("Cloudflare API rejected DDNS request")
	}
	if result != nil {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

func (s *Service) updateCloudflare(ctx context.Context, ip string) error {
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := s.cloudflare(ctx, "GET", "/zones?name="+url.QueryEscape(s.config.ZoneName), nil, &zones); err != nil {
		return err
	}
	if len(zones) != 1 || zones[0].ID == "" || !strings.EqualFold(zones[0].Name, s.config.ZoneName) {
		return errors.New("Cloudflare DDNS zone not found or not uniquely authorized; check ZoneName and token scope")
	}
	base := "/zones/" + url.PathEscape(zones[0].ID) + "/dns_records"
	query := url.Values{"name": {s.config.Domain}, "type": {s.config.RecordType}, "per_page": {"100"}}
	var records []cfRecord
	if err := s.cloudflare(ctx, "GET", base+"?"+query.Encode(), nil, &records); err != nil {
		return err
	}
	if len(records) > 1 {
		return errors.New("multiple DDNS records match; keep a single A/AAAA record for this hostname")
	}
	if len(records) == 0 {
		return s.recordUpdated(ip, s.cloudflare(ctx, "POST", base, map[string]any{
			"type": s.config.RecordType, "name": s.config.Domain, "content": ip,
			"ttl": s.config.TTL, "proxied": false,
		}, nil))
	}
	r := records[0]
	if r.ID == "" || !strings.EqualFold(r.Name, s.config.Domain) || r.Type != s.config.RecordType {
		return errors.New("Cloudflare returned an unexpected DDNS record")
	}
	if sameIP(r.Content, ip) {
		return nil
	}
	// PATCH only the address, preserving proxy status, TTL, tags and comments.
	return s.recordUpdated(ip, s.cloudflare(ctx, "PATCH", base+"/"+url.PathEscape(r.ID), map[string]string{"content": ip}, nil))
}
