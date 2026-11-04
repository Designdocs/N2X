package conf

import (
	"fmt"
	"io"
	"os"

	"github.com/Designdocs/N2X/common/json5"
)

type Conf struct {
	LogConfig        LogConfig              `json:"Log"`
	CoresConfig      []CoreConfig           `json:"Cores"`
	NodeConfig       []NodeConfig           `json:"Nodes"`
	MemoryConfig     MemoryConfig           `json:"Memory"`
	ScheduledRestart ScheduledRestartConfig `json:"ScheduledRestart"`
	// Warnings lists problems LoadValidated found that do not stop the config
	// from being used. It is never read from the file.
	Warnings []Issue `json:"-"`
	// Detached before cores can mutate decoded options during startup.
	loadedWatchState *watchState
}

func New() *Conf {
	return &Conf{
		MemoryConfig:     MemoryConfig{SoftLimitPercent: 70, RestartPercent: 90},
		ScheduledRestart: ScheduledRestartConfig{IntervalDays: 3, StartTime: "03:00", EndTime: "05:00"},
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %w", err)
	}
	defer f.Close()

	reader := json5.NewTrimNodeReader(f)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read config file error: %w", err)
	}

	if err := p.decode(data); err != nil {
		return fmt.Errorf("unmarshal config error: %w", err)
	}
	return nil
}
