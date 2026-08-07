package cmd

import (
	"fmt"
	"sort"
	"strings"

	vCore "github.com/Designdocs/N2X/core"
	"github.com/spf13/cobra"
)

var (
	version  = "TempVersion" //use ldflags replace
	codename = "N2X"
	intro    = "A V2board backend based on multi core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

func showVersion() {
	fmt.Println(` 
  _/      _/    _/_/    _/        _/      _/   
 _/      _/  _/    _/  _/_/_/      _/  _/      
_/      _/      _/    _/    _/      _/         
 _/  _/      _/      _/    _/    _/  _/        
  _/      _/_/_/_/  _/_/_/    _/      _/        
                                                `)
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
	// Which cores are linked in depends on the build tags, and so does which
	// protocols the binary can serve. Print it so an operator can tell at a
	// glance whether e.g. the sing core is present.
	cores := vCore.RegisteredCore()
	sort.Strings(cores)
	if len(cores) == 0 {
		fmt.Println("Supported cores: none (built without any core build tag)")
	} else {
		fmt.Printf("Supported cores: %s\n", strings.Join(cores, ", "))
	}
	// Warning
	//fmt.Println(Warn("This version need V2board version >= 1.7.0."))
	//fmt.Println(Warn("The version have many changed for config, please check your config file"))
}
