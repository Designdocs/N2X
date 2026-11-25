package conf

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"

	"encoding/json"

	"github.com/Designdocs/N2X/common/json5"
)

type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

type rawNodeConfig struct {
	Include string          `json:"Include"`
	ApiRaw  json.RawMessage `json:"ApiConfig"`
	OptRaw  json.RawMessage `json:"Options"`
}

type ApiConfig struct {
	APIHost      string          `json:"ApiHost"`
	APISendIP    string          `json:"ApiSendIP"`
	NodeID       int             `json:"NodeID"`
	Key          string          `json:"ApiKey"`
	NodeType     string          `json:"NodeType"`
	Timeout      int             `json:"Timeout"`
	RuleListPath string          `json:"RuleListPath"`
	WebSocket    WebSocketConfig `json:"WebSocket"`
}

// WebSocketConfig controls the optional WebSocket driver that talks to the
// X-Board /ws/ endpoint. Default zero value keeps the driver disabled so an
// N2X upgrade is a no-op for existing deployments; flip Enabled to true only
// after verifying panel support.
type WebSocketConfig struct {
	// Enabled opts in to the WS driver. Leave false to stay on pure HTTP.
	Enabled bool `json:"Enabled"`
	// URL is the full ws:// or wss:// endpoint, e.g. wss://api.example.com/ws/.
	// When empty the driver derives it from ApiHost (http -> ws, https -> wss)
	// and appends /ws/.
	URL string `json:"URL"`
	// Debug enables verbose per-message logs; use while commissioning.
	Debug bool `json:"Debug"`
}

func (n *NodeConfig) UnmarshalJSON(data []byte) (err error) {
	rn := rawNodeConfig{}
	data, err = resolveEnvPlaceholders(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &rn)
	if err != nil {
		return err
	}
	if len(rn.Include) != 0 {
		file, _ := strings.CutPrefix(rn.Include, ":")
		switch file {
		case "http", "https":
			rsp, err := http.Get(file)
			if err != nil {
				return err
			}
			defer rsp.Body.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(rsp.Body))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		default:
			f, err := os.Open(rn.Include)
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
			defer f.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(f))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		}
		data, err = resolveEnvPlaceholders(data)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &rn)
		if err != nil {
			return fmt.Errorf("unmarshal include file error: %s", err)
		}
	}

	n.ApiConfig = ApiConfig{
		APIHost: "http://127.0.0.1",
		Timeout: 30,
	}
	if len(rn.ApiRaw) > 0 {
		err = json.Unmarshal(rn.ApiRaw, &n.ApiConfig)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.ApiConfig)
		if err != nil {
			return
		}
	}

	n.Options = Options{
		ListenIP:   "0.0.0.0",
		SendIP:     "0.0.0.0",
		CertConfig: NewCertConfig(),
	}
	if len(rn.OptRaw) > 0 {
		err = json.Unmarshal(rn.OptRaw, &n.Options)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.Options)
		if err != nil {
			return
		}
	}
	return
}

// RealityFallbackLimit applies to one direction of an unauthenticated connection.
type RealityFallbackLimit struct {
	AfterBytes       uint64 `json:"afterBytes"`
	BytesPerSec      uint64 `json:"bytesPerSec"`
	BurstBytesPerSec uint64 `json:"burstBytesPerSec"`
}

type Options struct {
	LimitFallbackUpload    *RealityFallbackLimit `json:"limitFallbackUpload,omitempty"`
	LimitFallbackDownload  *RealityFallbackLimit `json:"limitFallbackDownload,omitempty"`
	Name                   string                `json:"Name"`
	Core                   string                `json:"Core"`
	CoreName               string                `json:"CoreName"`
	ListenIP               string                `json:"ListenIP"`
	SendIP                 string                `json:"SendIP"`
	DeviceOnlineMinTraffic int64                 `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64                 `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig           `json:"LimitConfig"`
	RawOptions             json.RawMessage       `json:"RawOptions"`
	XrayOptions            *XrayOptions          `json:"XrayOptions"`
	SingOptions            *SingOptions          `json:"SingOptions"`
	ArtXOptions            *ArtXOptions          `json:"ArtXOptions"`
	CertConfig             *CertConfig           `json:"CertConfig"`
	DDNSConfig             DDNSConfig            `json:"DDNSConfig"`
}

// CheckRealityFallbackLimits also runs after automatic core selection.
func (o *Options) CheckRealityFallbackLimits(coreType string) error {
	for _, direction := range []struct {
		name  string
		limit *RealityFallbackLimit
	}{
		{"limitFallbackUpload", o.LimitFallbackUpload},
		{"limitFallbackDownload", o.LimitFallbackDownload},
	} {
		if direction.limit == nil {
			continue
		}
		if coreType == "sing" {
			return fmt.Errorf("%s requires Xray REALITY; sing-box does not support REALITY fallback rate limits", direction.name)
		}
		// Xray uses signed byte counts for the allowance and token bucket.
		l := direction.limit
		if l.AfterBytes > math.MaxInt64 || l.BytesPerSec > math.MaxInt64 || l.BurstBytesPerSec > math.MaxInt64 {
			return fmt.Errorf("%s byte counts must fit in a signed 64-bit integer", direction.name)
		}
	}
	return nil
}

func (o *Options) UnmarshalJSON(data []byte) error {
	type opt Options
	err := json.Unmarshal(data, (*opt)(o))
	if err != nil {
		return err
	}
	switch o.Core {
	case "xray":
		o.XrayOptions = NewXrayOptions()
		return json.Unmarshal(data, o.XrayOptions)
	case "sing":
		o.SingOptions = NewSingOptions()
		return json.Unmarshal(data, o.SingOptions)
	default:
		o.Core = ""
		o.RawOptions = data
	}
	return nil
}
