package cmd

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/Designdocs/N2X/node"
	log "github.com/sirupsen/logrus"
)

// problemCategory orders the startup summary: problems in the file itself
// come first, since fixing them usually clears the rest.
type problemCategory int

const (
	categorySyntax problemCategory = iota
	categoryConfig
	categoryCert
	categoryPanel
	categoryCore
)

var categoryLabels = map[problemCategory]string{
	categorySyntax: "格式错误",
	categoryConfig: "配置错误",
	categoryCert:   "证书错误",
	categoryPanel:  "面板错误",
	categoryCore:   "生成错误",
}

const (
	// maxProblemMessageRunes keeps each summary line short; the full error
	// is already in the log line printed when the problem happened.
	maxProblemMessageRunes = 300
	reportRule             = "=========="
	warningLabel           = "警告"
)

type startupProblem struct {
	category problemCategory
	where    string
	message  string
	// warning marks a problem that did not stop anything from starting.
	warning bool
}

// startupReport collects what went wrong while the server started or
// reloaded, and prints it as one short block with a line per problem, each
// tagged with its category so it can be found with a single grep.
type startupReport struct {
	problems []startupProblem
}

func (r *startupReport) add(category problemCategory, where, message string) {
	r.problems = append(r.problems, startupProblem{category: category, where: where, message: message})
}

// addConfigError records a config that failed to load: every issue and
// warning of a validation error, or the error itself when the file could not
// be read.
func (r *startupReport) addConfigError(err error) {
	var validationErr *conf.ValidationError
	if !errors.As(err, &validationErr) {
		r.add(categoryConfig, "", err.Error())
		return
	}
	for _, issue := range validationErr.Issues {
		r.add(issueCategory(issue.Kind), issue.Path, issue.Message)
	}
	r.addWarnings(validationErr.Warnings)
}

// addWarnings records config problems that did not stop the config from
// being used.
func (r *startupReport) addWarnings(issues []conf.Issue) {
	for _, issue := range issues {
		r.addWarning(issueCategory(issue.Kind), issue.Path, issue.Message)
	}
}

// addWarning records a problem that did not stop anything from starting.
func (r *startupReport) addWarning(category problemCategory, where, message string) {
	r.problems = append(r.problems, startupProblem{category: category, where: where, message: message, warning: true})
}

func issueCategory(kind conf.IssueKind) problemCategory {
	switch kind {
	case conf.IssueSyntax:
		return categorySyntax
	case conf.IssueCert:
		return categoryCert
	default:
		return categoryConfig
	}
}

// addNodeFailures records nodes whose first start attempt failed, located by
// their index in the config and their panel type and ID.
func (r *startupReport) addNodeFailures(nodes []conf.NodeConfig, failures []node.StartFailure) {
	for _, failure := range failures {
		where := fmt.Sprintf("Nodes[%d]", failure.Index)
		if failure.Index >= 0 && failure.Index < len(nodes) {
			api := nodes[failure.Index].ApiConfig
			where = fmt.Sprintf("%s (%s #%d)", where, api.NodeType, api.NodeID)
		}
		r.add(stageCategory(failure.Stage), where, failure.Err.Error())
	}
}

func stageCategory(stage node.StartStage) problemCategory {
	switch stage {
	case node.StagePanel:
		return categoryPanel
	case node.StageCert:
		return categoryCert
	default:
		return categoryCore
	}
}

func (r *startupReport) empty() bool { return len(r.problems) == 0 }

// render returns the summary lines, errors first and warnings after them.
// title names the operation, e.g. "N2X 启动"; the summary is called an error
// summary unless every problem is a warning. outcome says what the server did
// about the problems and hint where to look next; either may be empty.
func (r *startupReport) render(title, outcome, hint string) []string {
	problems := slices.Clone(r.problems)
	slices.SortStableFunc(problems, func(a, b startupProblem) int {
		if a.warning != b.warning {
			if a.warning {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.category, b.category)
	})

	counts := map[problemCategory]int{}
	warnings := 0
	for _, problem := range problems {
		if problem.warning {
			warnings++
			continue
		}
		counts[problem.category]++
	}
	var tally []string
	for category := categorySyntax; category <= categoryCore; category++ {
		if counts[category] > 0 {
			tally = append(tally, fmt.Sprintf("%s %d", categoryLabels[category], counts[category]))
		}
	}
	kind := "错误摘要"
	if warnings > 0 {
		tally = append(tally, fmt.Sprintf("%s %d", warningLabel, warnings))
		if warnings == len(problems) {
			kind = warningLabel + "摘要"
		}
	}

	lines := []string{fmt.Sprintf("%s %s%s（共 %d 项：%s）%s", reportRule, title, kind, len(problems), strings.Join(tally, "，"), reportRule)}
	for _, problem := range problems {
		message := shortenMessage(problem.message)
		if problem.where != "" {
			message = problem.where + ": " + message
		}
		label := fmt.Sprintf("[%s]", categoryLabels[problem.category])
		if problem.warning {
			label = fmt.Sprintf("[%s] %s", warningLabel, label)
		}
		lines = append(lines, label+" "+message)
	}
	if outcome != "" {
		lines = append(lines, "结果: "+outcome)
	}
	if hint != "" {
		lines = append(lines, "排查: "+hint)
	}
	return append(lines, strings.Repeat(reportRule, 4))
}

// shortenMessage folds a message onto one line, masks the panel API key and
// cuts it to maxProblemMessageRunes. The panel client already masks the key
// in its own errors; masking again covers messages from anywhere else.
func shortenMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	message = panel.RedactToken(message)
	if runes := []rune(message); len(runes) > maxProblemMessageRunes {
		return string(runes[:maxProblemMessageRunes]) + "…"
	}
	return message
}

// publish prints the summary to stderr, where the terminal and journald see
// it, and copies it into the log when the log has been sent elsewhere. An
// empty report prints nothing.
func (r *startupReport) publish(stderr io.Writer, logger *log.Logger, title, outcome, hint string) {
	if r.empty() {
		return
	}
	lines := r.render(title, outcome, hint)
	fmt.Fprintln(stderr, strings.Join(lines, "\n"))
	// logrus writes to os.Stderr itself until Log.Output replaces it, so an
	// identical writer means the copy would print the summary twice.
	if logger.Out == stderr {
		return
	}
	for _, line := range lines {
		logger.Error(line)
	}
}
