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
	Use:          "server",
	Short:        "Run N2X server",
	RunE:         serverHandle,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	// Run logs the returned error; cobra printing it again would duplicate it.
	SilenceErrors: true,
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

// loadEnvFile loads envFile, or the .env next to the config file when envFile
// is empty. interactive allows offering to create a missing default file.
func loadEnvFile(configPath, envFile string, interactive bool) {
	if envFile != "" {
		if err := envfile.Load(envFile, false); err != nil {
			log.WithField("err", err).Warn("Load env file failed, fallback to config.json values")
		}
		return
	}
	defaultEnv := filepath.Join(filepath.Dir(configPath), ".env")
	_, err := os.Stat(defaultEnv)
	switch {
	case err == nil:
		if err := envfile.Load(defaultEnv, false); err != nil {
			log.WithField("err", err).Warn("Load default env file failed, fallback to config.json values")
		}
	case errors.Is(err, os.ErrNotExist) && interactive && promptCreateEnv(defaultEnv):
		if err := envfile.Load(defaultEnv, false); err != nil {
			log.WithField("err", err).Warn("Load newly created env file failed, fallback to config.json values")
		}
	default:
		log.WithField("path", defaultEnv).Info("Env file not found, fallback to config.json values")
	}
}

const (
	// Report titles name the operation; render adds 错误摘要 or 警告摘要.
	startupReportTitle = "N2X 启动"
	reloadReportTitle  = "N2X 重载"
	seeLogHint         = "完整错误见上方日志"
)

// checkHint points at the command that re-runs the full config check.
func checkHint(configPath string) string {
	return fmt.Sprintf("修改后运行 N2X check -c %s 复查（数组下标从 0 开始）", configPath)
}

// startedHint says where to look after a start in which the core came up:
// the log when nodes failed, otherwise the config check for its warnings.
func startedHint(failedNodes int, configPath string) string {
	if failedNodes > 0 {
		return seeLogHint
	}
	return checkHint(configPath)
}

// dnsWatchPath returns the xray DNS file to watch for changes, or "" when
// there is none. A file that does not exist yet is watched through its
// directory; a missing directory cannot be watched, which is returned as an
// error but must not stop the server.
func dnsWatchPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("DNS file changes are not watched: %w", err)
	}
	return path, nil
}

func publishReport(report *startupReport, title, outcome, hint string) {
	report.publish(os.Stderr, log.StandardLogger(), title, outcome, hint)
}

// nodesOutcome describes a start in which the core came up.
func nodesOutcome(failed, total int) string {
	switch failed {
	case 0:
		return "核心与节点均已启动"
	case total:
		return fmt.Sprintf("核心已启动；全部 %d 个节点启动失败，失败的节点在后台自动重试", total)
	}
	return fmt.Sprintf("核心已启动；%d/%d 个节点启动失败，其余节点正常运行，失败的节点在后台自动重试", failed, total)
}

func serverHandle(_ *cobra.Command, _ []string) error {
	showVersion()
	loadEnvFile(config, envF, true)
	var report startupReport
	c, err := loadConfig(config)
	if err != nil {
		report.addConfigError(err)
		publishReport(&report, startupReportTitle, "未启动任何核心和节点，进程退出", checkHint(config))
		return errors.New("invalid config file")
	}
	report.addWarnings(c.Warnings)
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
			report.add(categoryConfig, "Log.Output", fmt.Sprintf("open log file failed, logging to stderr instead: %v", err))
		} else {
			log.SetOutput(f)
		}
	}
	limiter.Init()
	log.Info("Start N2X...")
	vc, err := vCore.NewCore(c.CoresConfig)
	if err != nil {
		log.WithField("err", err).Error("new core failed")
		report.add(categoryCore, "Cores", fmt.Sprintf("new core: %v", err))
		publishReport(&report, startupReportTitle, "核心未创建，进程退出", seeLogHint)
		return fmt.Errorf("new core: %w", err)
	}
	err = vc.Start()
	if err != nil {
		log.WithField("err", err).Error("Start core failed")
		report.add(categoryCore, "Cores", fmt.Sprintf("start core: %v", err))
		publishReport(&report, startupReportTitle, "核心未启动，进程退出", seeLogHint)
		return fmt.Errorf("start core: %w", err)
	}
	// A reload replaces vc; close whichever core is running at shutdown. The
	// watcher is stopped first (defers run in reverse), so vc is stable here.
	defer func() { vc.Close() }()
	log.Info("Core ", vc.Type(), " started")
	nodes := node.New()
	failures, err := nodes.Start(c.NodeConfig, vc)
	if err != nil {
		log.WithField("err", err).Error("Run nodes failed")
		report.add(categoryConfig, "", err.Error())
		publishReport(&report, startupReportTitle, "节点未启动，进程退出", checkHint(config))
		return fmt.Errorf("run nodes: %w", err)
	}
	report.addNodeFailures(c.NodeConfig, failures)
	var xdns string
	if watch {
		var dnsErr error
		if xdns, dnsErr = dnsWatchPath(os.Getenv("XRAY_DNS_PATH")); dnsErr != nil {
			log.WithField("err", dnsErr).Warn("DNS file is not watched for changes")
			report.addWarning(categoryConfig, "XRAY_DNS_PATH", dnsErr.Error())
		}
	}
	publishReport(&report, startupReportTitle, nodesOutcome(len(failures), len(c.NodeConfig)), startedHint(len(failures), config))
	log.Info("Nodes started")
	if watch {
		// A distinct name: the closure below assigns to the outer err.
		stopWatch, watchErr := c.Watch(config, xdns, validateOptions(), func() {
			var reloadReport startupReport
			reloadReport.addWarnings(c.Warnings)
			nodes.Close()
			err = vc.Close()
			if err != nil {
				log.WithField("err", err).Error("Restart node failed")
				return
			}
			vc, err = vCore.NewCore(c.CoresConfig)
			if err != nil {
				log.WithField("err", err).Error("New core failed")
				reloadReport.add(categoryCore, "Cores", fmt.Sprintf("new core: %v", err))
				publishReport(&reloadReport, reloadReportTitle, "核心未创建，所有节点已停止", seeLogHint)
				return
			}
			err = vc.Start()
			if err != nil {
				log.WithField("err", err).Error("Start core failed")
				reloadReport.add(categoryCore, "Cores", fmt.Sprintf("start core: %v", err))
				publishReport(&reloadReport, reloadReportTitle, "核心未启动，所有节点已停止", seeLogHint)
				return
			}
			log.Info("Core ", vc.Type(), " restarted")
			var failures []node.StartFailure
			failures, err = nodes.Start(c.NodeConfig, vc)
			if err != nil {
				log.WithField("err", err).Error("Run nodes failed")
				reloadReport.add(categoryConfig, "", err.Error())
				publishReport(&reloadReport, reloadReportTitle, "节点未启动", checkHint(config))
				return
			}
			reloadReport.addNodeFailures(c.NodeConfig, failures)
			publishReport(&reloadReport, reloadReportTitle, nodesOutcome(len(failures), len(c.NodeConfig)), startedHint(len(failures), config))
			log.Info("Nodes restarted")
			runtime.GC()
		}, func(rejectErr error) {
			var rejectReport startupReport
			rejectReport.addConfigError(rejectErr)
			publishReport(&rejectReport, reloadReportTitle, "新配置未生效，继续使用原配置运行", checkHint(config))
		})
		if watchErr != nil {
			log.WithField("err", watchErr).Error("start watch failed")
			return fmt.Errorf("start watch: %w", watchErr)
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
	return nil
}
