package limiter

import (
	"fmt"
	"regexp"

	"github.com/Designdocs/N2X/api/panel"
)

func (l *Limiter) CheckDomainRule(destination string) (reject bool) {
	// have rule
	for i := range l.DomainRules {
		if l.DomainRules[i].MatchString(destination) {
			reject = true
			break
		}
	}
	return
}

func (l *Limiter) CheckProtocolRule(protocol string) (reject bool) {
	for i := range l.ProtocolRules {
		if l.ProtocolRules[i] == protocol {
			reject = true
			break
		}
	}
	return
}

func (l *Limiter) UpdateRule(rule *panel.Rules) error {
	domainRules := make([]*regexp.Regexp, len(rule.Regexp))
	for i, pattern := range rule.Regexp {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid domain rule %d: %w", i, err)
		}
		domainRules[i] = compiled
	}
	l.DomainRules = domainRules
	l.ProtocolRules = rule.Protocol
	return nil
}
