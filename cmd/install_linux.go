package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Designdocs/N2X/common/exec"
	"github.com/spf13/cobra"
)

var targetVersion string

var (
	updateCommand = cobra.Command{
		Use:   "update",
		Short: "Update N2X version",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("bash",
				"<(curl -Ls https://raw.githubusercontents.com/InazumaV/N2X-script/master/install.sh)",
				targetVersion)
		},
		Args: cobra.NoArgs,
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall N2X",
		Run:   uninstallHandle,
	}
)

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "update target version")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
}

func uninstallHandle(_ *cobra.Command, _ []string) {
	var yes string
	fmt.Println(Warn("确定要卸载 N2X 吗?(Y/n)"))
	fmt.Scan(&yes)
	if strings.ToLower(yes) != "y" {
		fmt.Println("已取消卸载")
	}
	_, err := exec.RunCommandByShell("systemctl stop N2X&&systemctl disable N2X")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("卸载失败"))
		return
	}
	_ = os.RemoveAll("/etc/systemd/system/N2X.service")
	_ = os.RemoveAll("/etc/N2X/")
	_ = os.RemoveAll("/usr/local/N2X/")
	_ = os.RemoveAll("/bin/N2X")
	_, err = exec.RunCommandByShell("systemctl daemon-reload&&systemctl reset-failed")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("卸载失败"))
		return
	}
	fmt.Println(Ok("卸载成功"))
}
