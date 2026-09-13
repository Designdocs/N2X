package node

import (
	"errors"
	"fmt"
)

// StartStage names the step at which a node failed to start, so a startup
// summary can tell a panel outage from a certificate or core problem.
type StartStage string

const (
	// StagePanel covers fetching the node settings and users from the panel.
	StagePanel StartStage = "panel"
	// StageCert covers obtaining or loading the node's certificate.
	StageCert StartStage = "cert"
	// StageCore covers building the node in the core: rules, inbound, users.
	StageCore StartStage = "core"
)

// StartFailure is a node whose first start attempt failed. The node keeps
// retrying in the background; this only records why the first attempt did not
// come up.
type StartFailure struct {
	// Index is the node's position in the Nodes array of the config.
	Index int
	Stage StartStage
	Err   error
}

// stageError tags an error with the start stage it came from without
// changing its message.
type stageError struct {
	stage StartStage
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }

func (e *stageError) Unwrap() error { return e.err }

func startError(stage StartStage, format string, args ...any) error {
	return &stageError{stage: stage, err: fmt.Errorf(format, args...)}
}

// startStageOf returns the stage err was tagged with, or StageCore for an
// untagged error: everything past the panel and certificate steps builds the
// node in the core.
func startStageOf(err error) StartStage {
	var tagged *stageError
	if errors.As(err, &tagged) {
		return tagged.stage
	}
	return StageCore
}
