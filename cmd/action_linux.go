package cmd

import (
	"fmt"
	"time"

	"github.com/Designdocs/N2X/common/exec"
	"github.com/spf13/cobra"
)

var (
	startCommand = cobra.Command{
		Use:   "start",
		Short: "Start N2X service",
		Run:   startHandle,
	}
	stopCommand = cobra.Command{
		Use:   "stop",
		Short: "Stop N2X service",
		Run:   stopHandle,
	}
	restartCommand = cobra.Command{
		Use:   "restart",
		Short: "Restart N2X service",
		Run:   restartHandle,
	}
	logCommand = cobra.Command{
		Use:   "log",
		Short: "Output N2X log",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("journalctl", "-u", "N2X.service", "-e", "--no-pager", "-f")
		},
	}
)

func init() {
	command.AddCommand(&startCommand)
	command.AddCommand(&stopCommand)
	command.AddCommand(&restartCommand)
	command.AddCommand(&logCommand)
}

func startHandle(_ *cobra.Command, _ []string) {
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("N2X启动失败"))
		return
	}
	if r {
		fmt.Println(Ok("N2X已运行，无需再次启动，如需重启请选择重启"))
	}
	_, err = exec.RunCommandByShell("systemctl start N2X.service")
	if err != nil {
		fmt.Println(Err("exec start cmd error: ", err))
		fmt.Println(Err("N2X启动失败"))
		return
	}
	time.Sleep(time.Second * 3)
	r, err = checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("N2X启动失败"))
	}
	if !r {
		fmt.Println(Err("N2X可能启动失败，请稍后使用 N2X log 查看日志信息"))
		return
	}
	fmt.Println(Ok("N2X 启动成功，请使用 N2X log 查看运行日志"))
}

func stopHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl stop N2X.service")
	if err != nil {
		fmt.Println(Err("exec stop cmd error: ", err))
		fmt.Println(Err("N2X停止失败"))
		return
	}
	time.Sleep(2 * time.Second)
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error:", err))
		fmt.Println(Err("N2X停止失败"))
		return
	}
	if r {
		fmt.Println(Err("N2X停止失败，可能是因为停止时间超过了两秒，请稍后查看日志信息"))
		return
	}
	fmt.Println(Ok("N2X 停止成功"))
}

func restartHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl restart N2X.service")
	if err != nil {
		fmt.Println(Err("exec restart cmd error: ", err))
		fmt.Println(Err("N2X重启失败"))
		return
	}
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("N2X重启失败"))
		return
	}
	if !r {
		fmt.Println(Err("N2X可能启动失败，请稍后使用 N2X log 查看日志信息"))
		return
	}
	fmt.Println(Ok("N2X重启成功"))
}
