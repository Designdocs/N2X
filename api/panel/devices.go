package panel

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"encoding/json"
)

func decodeDeviceAliveMap(raw json.RawMessage) (map[int]int, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[int]int{}, nil
	}

	devicesRaw, err := extractDeviceUsers(raw)
	if err != nil {
		return nil, err
	}

	var devices map[string]json.RawMessage
	if err := json.Unmarshal(devicesRaw, &devices); err != nil {
		return nil, fmt.Errorf("decode device users: %w", err)
	}

	alive := make(map[int]int, len(devices))
	for rawUID, rawIPs := range devices {
		uid, err := strconv.Atoi(rawUID)
		if err != nil || uid <= 0 {
			continue
		}
		count, err := countDeviceIPs(rawIPs)
		if err != nil {
			continue
		}
		if count > 0 {
			alive[uid] = count
		}
	}
	return alive, nil
}

func extractDeviceUsers(raw json.RawMessage) (json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode device envelope: %w", err)
	}
	if users, ok := envelope["users"]; ok {
		return users, nil
	}
	if devices, ok := envelope["devices"]; ok {
		return devices, nil
	}
	return raw, nil
}

func countDeviceIPs(raw json.RawMessage) (int, error) {
	var count int
	if err := json.Unmarshal(raw, &count); err == nil {
		if count < 0 {
			return 0, nil
		}
		return count, nil
	}

	ips := make(map[string]struct{})
	if err := appendDeviceIPsFromArray(raw, ips); err == nil {
		return len(ips), nil
	}
	if err := appendDeviceIPsFromObject(raw, ips); err == nil {
		return len(ips), nil
	}
	return 0, fmt.Errorf("unsupported device ip payload")
}

func appendDeviceIPsFromArray(raw json.RawMessage, ips map[string]struct{}) error {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	for _, value := range values {
		addDeviceIP(ips, value)
	}
	return nil
}

func appendDeviceIPsFromObject(raw json.RawMessage, ips map[string]struct{}) error {
	var values map[string]string
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	for _, value := range values {
		addDeviceIP(ips, value)
	}
	return nil
}

func addDeviceIP(ips map[string]struct{}, ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	ip = normalizeDeviceIP(ip)
	ips[ip] = struct{}{}
}

func normalizeDeviceIP(ip string) string {
	host, port, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ip
	}
	return host
}

func copyAliveMap(alive map[int]int) map[int]int {
	copied := make(map[int]int, len(alive))
	for uid, count := range alive {
		if uid > 0 && count > 0 {
			copied[uid] = count
		}
	}
	return copied
}
