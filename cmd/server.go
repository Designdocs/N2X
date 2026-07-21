package cmd

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Designdocs/N2X/common/envfile"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
	"github.com/Designdocs/N2X/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// promptCreateEnv asks the user whether to create an env file and, if agreed,
// guides through filling the key values. It returns true if a file was created.
func promptCreateEnv(envPath string) bool {
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeCharDevice == 0 {
		// 非交互环境（如 systemd）不提示，直接跳过
		return false
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("检测到缺少 %s，是否现在创建? [y/N]: ", envPath)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		return false
	}

	dir := filepath.Dir(envPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.WithField("err", err).Error("创建 env 目录失败")
		return false
	}

	type q struct {
		Key      string
		Prompt   string
		Default  string
		Required bool
	}

	questions := []q{
		{Key: "N2X_API_HOST", Prompt: "面板 API 地址 (N2X_API_HOST)", Default: "http://127.0.0.1", Required: true},
		{Key: "N2X_API_KEY", Prompt: "面板 API 密钥 (N2X_API_KEY)", Default: "", Required: true},
		{Key: "N2X_CERT_PROVIDER", Prompt: "证书提供商 (N2X_CERT_PROVIDER)", Default: "cloudflare", Required: false},
		{Key: "N2X_CERT_EMAIL", Prompt: "证书邮箱 (N2X_CERT_EMAIL)", Default: "", Required: false},
		{Key: "CF_API_KEY", Prompt: "Cloudflare API Key (CF_API_KEY)", Default: "", Required: false},
		{Key: "CLOUDFLARE_EMAIL", Prompt: "Cloudflare 邮箱 (CLOUDFLARE_EMAIL)", Default: "", Required: false},
		{Key: "N2X_CERT_DOMAIN", Prompt: "证书域名 (N2X_CERT_DOMAIN)", Default: "example.com", Required: false},
	}

	values := make(map[string]string, len(questions))
	for _, item := range questions {
		for {
			defHint := ""
			if item.Default != "" {
				defHint = fmt.Sprintf(" [默认: %s]", item.Default)
			}
			fmt.Printf("%s%s: ", item.Prompt, defHint)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" {
				if item.Default != "" {
					input = item.Default
				} else {
					input = randomValue()
					fmt.Printf("已自动生成随机值: %s\n", input)
				}
			}
			values[item.Key] = input
			break
		}
	}

	f, err := os.OpenFile(envPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.WithField("err", err).Error("创建 env 文件失败")
		return false
	}
	defer f.Close()

	for _, item := range questions {
		fmt.Fprintf(f, "%s=%s\n", item.Key, values[item.Key])
	}

	fmt.Printf("已创建 %s 并写入配置。\n", envPath)
	return true
}

func randomValue() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 回退到时间戳式伪随机
		return fmt.Sprintf("rand-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

var (
	config string
	watch  bool
	envF   string
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run N2X server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/N2X/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	serverCommand.PersistentFlags().
		StringVarP(&envF, "env-file", "e",
			"", "env file path")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	if envF != "" {
		if err := envfile.Load(envF, false); err != nil {
			log.WithField("err", err).Warn("Load env file failed, fallback to config.json values")
		}
	} else {
		defaultEnv := filepath.Join(filepath.Dir(config), ".env")
		if _, err := os.Stat(defaultEnv); err == nil {
			if err := envfile.Load(defaultEnv, false); err != nil {
				log.WithField("err", err).Warn("Load default env file failed, fallback to config.json values")
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if created := promptCreateEnv(defaultEnv); created {
				if err := envfile.Load(defaultEnv, false); err != nil {
					log.WithField("err", err).Warn("Load newly created env file failed, fallback to config.json values")
				}
			} else {
				log.WithField("path", defaultEnv).Info("Env file not found, fallback to config.json values")
			}
		} else {
			log.WithField("path", defaultEnv).Info("Env file not found, fallback to config.json values")
		}
	}
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		}
		log.SetOutput(f)
	}
	limiter.Init()
	log.Info("Start N2X...")
	vc, err := vCore.NewCore(c.CoresConfig)
	if err != nil {
		log.WithField("err", err).Error("new core failed")
		return
	}
	err = vc.Start()
	if err != nil {
		log.WithField("err", err).Error("Start core failed")
		return
	}
	defer vc.Close()
	log.Info("Core ", vc.Type(), " started")
	nodes := node.New()
	err = nodes.Start(c.NodeConfig, vc)
	if err != nil {
		log.WithField("err", err).Error("Run nodes failed")
		return
	}
	log.Info("Nodes started")
	xdns := os.Getenv("XRAY_DNS_PATH")
	if watch {
		// A distinct name: the closure below assigns to the outer err.
		stopWatch, watchErr := c.Watch(config, xdns, func() {
			nodes.Close()
			err = vc.Close()
			if err != nil {
				log.WithField("err", err).Error("Restart node failed")
				return
			}
			vc, err = vCore.NewCore(c.CoresConfig)
			if err != nil {
				log.WithField("err", err).Error("New core failed")
				return
			}
			err = vc.Start()
			if err != nil {
				log.WithField("err", err).Error("Start core failed")
				return
			}
			log.Info("Core ", vc.Type(), " restarted")
			err = nodes.Start(c.NodeConfig, vc)
			if err != nil {
				log.WithField("err", err).Error("Run nodes failed")
				return
			}
			log.Info("Nodes restarted")
			runtime.GC()
		})
		if watchErr != nil {
			log.WithField("err", watchErr).Error("start watch failed")
			return
		}
		defer stopWatch()
	}
	// clear memory
	runtime.GC()
	// wait exit signal
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
		<-osSignals
	}
}
