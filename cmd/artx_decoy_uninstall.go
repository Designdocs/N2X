package cmd

const artXDecoyServiceFile = "/etc/systemd/system/N2X-artx-decoy.service"

type shellCommandRunner func(string) (string, error)
type fileRemover func(string) error

func cleanupArtXDecoyService(run shellCommandRunner, remove fileRemover) {
	for _, command := range []string{
		"systemctl stop N2X-artx-decoy",
		"systemctl disable N2X-artx-decoy",
	} {
		_, _ = run(command)
	}
	_ = remove(artXDecoyServiceFile)
}
