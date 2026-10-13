package conf

type MemoryConfig struct {
	SoftLimitPercent int `json:"SoftLimitPercent"`
	RestartPercent   int `json:"RestartPercent"`
}
