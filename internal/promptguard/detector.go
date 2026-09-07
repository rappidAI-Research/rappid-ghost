package promptguard

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type rule struct {
	id       string
	category Category
	pattern  *regexp.Regexp
}

var detectionRules = []rule{
	{id: "override-prior-authority", category: InstructionOverride, pattern: regexp.MustCompile(`\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|system|developer|security|all)\b.{0,60}\b(instruction|instructions|message|messages|rule|rules|policy|policies)\b`)},
	{id: "replace-instructions", category: InstructionOverride, pattern: regexp.MustCompile(`\b(follow|obey|use)\b.{0,60}\b(these|my|following|new)\b.{0,30}\b(instruction|instructions|rules)\b.{0,40}\b(instead|only)\b`)},
	{id: "disable-security", category: SecurityBypass, pattern: regexp.MustCompile(`\b(disable|bypass|circumvent|evade|turn off)\b.{0,80}\b(ghost|security|sandbox|isolation|container|network|proxy|policy|guard|restriction|restrictions)\b`)},
	{id: "remove-security-control", category: SecurityBypass, pattern: regexp.MustCompile(`\bremove\b.{0,80}\b(security|sandbox|isolation|network policy|proxy control|guard|restriction|restrictions)\b`)},
	{id: "credential-access", category: CredentialAccess, pattern: regexp.MustCompile(`\b(read|open|cat|copy|collect|steal|obtain|access|print|dump)\b.{0,64}(credential|credentials|secret|secrets|token|tokens|api[_ -]?key|private[_ -]?key|\.aws/credentials|\.ssh/id_rsa|/etc/shadow)\b`)},
	{id: "credential-path-command", category: CredentialAccess, pattern: regexp.MustCompile(`\b(cat|cp|sed|awk|grep|head|tail)\b.{0,64}(~|/home/[^ ]+)/\.(aws/credentials|ssh/id_rsa|env)\b`)},
	{id: "network-transmission", category: NetworkTransmission, pattern: regexp.MustCompile(`\b(send|upload|post|transmit|exfiltrate|forward|submit|curl|wget)\b.{0,96}\b(http|https|url|server|endpoint|webhook|domain|network|attacker)\b`)},
	{id: "environment-exposure", category: EnvironmentExposure, pattern: regexp.MustCompile(`\b(print|dump|expose|read|send|upload|collect)\b.{0,80}\b(environment variables|environment variable|env vars|env var|printenv|os\.environ)\b`)},
	{id: "security-setting-change", category: SecuritySettingChange, pattern: regexp.MustCompile(`\b(change|modify|edit|rewrite|override)\b.{0,80}\b(ghost\.yaml|tool permission|tool permissions|security setting|security settings|sandbox setting|sandbox settings|network policy)\b`)},
	{id: "authority-impersonation", category: AuthorityImpersonation, pattern: regexp.MustCompile(`(^|\s)(<system>|\[system\]|system message:|developer message:|tool call:|assistant to=)`)},
	{id: "conceal-action", category: Concealment, pattern: regexp.MustCompile(`\b(do not tell|don't tell|hide from|conceal from|without (the )?user knowing|do not mention|don't mention|secretly)\b`)},
}

var (
	base64Token       = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	defensiveLanguage = regexp.MustCompile(`\b(for example|example of|example below|malicious example|suspicious example|explain|explains|discussion|documentation|documented|detect|detection|detector|evidence|benchmark|scenario|synthetic|test|tests|fixture|finding|findings|rule|rules|protect|protection|prevent|prevents|prevention|mitigate|mitigation|deny|denies|reject|rejects|does not|not copied|exclude|excludes|omit|omits|test fixture|security research|must not execute|should not execute|never execute|do not execute|do not follow|quoted text)\b`)
	explicitDefense   = regexp.MustCompile(`\b(prevent|prevents|protect|protects|detect|detects|reject|rejects|deny|denies|mitigate|mitigates)\b.{0,100}\b(bypass|attack|prompt injection|credential|secret|exfiltration|unsafe)\b`)
	negativeExposure  = regexp.MustCompile(`\b(does not|do not|never)\b.{0,100}\b(read|copy|mount|expose|inherit|use|derive)\b.{0,100}\b(credential|credentials|secret|secrets|token|tokens|environment)\b`)
)

type matchSet struct {
	categories map[Category]bool
	rules      map[string]bool
	obfuscated bool
}

type textUnit struct {
	line int
	text string
}

func detect(sourcePath string, kind SourceKind, data []byte) (Finding, bool) {
	finding, found, _ := detectBounded(sourcePath, kind, data)
	return finding, found
}

const maxAnalysisLines = 4096

func detectBounded(sourcePath string, kind SourceKind, data []byte) (Finding, bool, bool) {
	lines := strings.Split(string(data), "\n")
	best := Finding{}
	found := false
	ranges := [][2]int{{0, len(lines)}}
	truncated := len(lines) > maxAnalysisLines
	if truncated {
		half := maxAnalysisLines / 2
		ranges = [][2]int{{0, half}, {len(lines) - half, len(lines)}}
	}
	for _, lineRange := range ranges {
		units := buildTextUnits(lines, lineRange[0], lineRange[1])
		for start := 0; start < len(units); start++ {
			end := start + 6
			if end > len(units) {
				end = len(units)
			}
			matches := matchSet{categories: make(map[Category]bool), rules: make(map[string]bool)}
			for index := start; index < end; index++ {
				mergeMatches(&matches, matchText(units[index].text, true))
			}
			if len(matches.categories) == 0 {
				continue
			}
			contextStart := start - 2
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := end + 2
			if contextEnd > len(units) {
				contextEnd = len(units)
			}
			contextParts := make([]string, 0, contextEnd-contextStart)
			for index := contextStart; index < contextEnd; index++ {
				contextParts = append(contextParts, units[index].text)
			}
			severity := classifySeverity(matches, kind, strings.Join(contextParts, "\n"))
			if !severity.Valid() {
				continue
			}
			candidate := Finding{
				SourcePath: sourcePath, SourceKind: kind, Severity: severity,
				Categories: sortedCategories(matches.categories), RuleIDs: sortedRules(matches.rules),
				Line: units[start].line, Fingerprint: fingerprint(data),
			}
			if !found || candidate.Severity.Rank() > best.Severity.Rank() ||
				(candidate.Severity == best.Severity && candidate.Line < best.Line) {
				best = candidate
				found = true
			}
		}
	}
	return best, found, truncated
}

func buildTextUnits(lines []string, start, end int) []textUnit {
	result := make([]textUnit, 0, end-start)
	var current *textUnit
	flush := func() {
		if current != nil {
			current.text = strings.TrimSpace(current.text)
			if current.text != "" {
				result = append(result, *current)
			}
			current = nil
		}
	}
	for index := start; index < end; index++ {
		trimmed := strings.TrimSpace(lines[index])
		if trimmed == "" {
			flush()
			continue
		}
		if startsMarkdownUnit(trimmed) {
			flush()
			current = &textUnit{line: index + 1, text: trimmed}
			continue
		}
		if current == nil {
			current = &textUnit{line: index + 1, text: trimmed}
		} else {
			current.text += " " + trimmed
		}
	}
	flush()
	return result
}

var numberedItem = regexp.MustCompile(`^[0-9]{1,3}[.)]\s`)

func startsMarkdownUnit(value string) bool {
	return strings.HasPrefix(value, "#") || strings.HasPrefix(value, "- ") || strings.HasPrefix(value, "* ") ||
		strings.HasPrefix(value, "+ ") || strings.HasPrefix(value, "```") || numberedItem.MatchString(value)
}

func mergeMatches(target *matchSet, source matchSet) {
	for category := range source.categories {
		target.categories[category] = true
	}
	for ruleID := range source.rules {
		target.rules[ruleID] = true
	}
	target.obfuscated = target.obfuscated || source.obfuscated
}

func matchText(value string, allowEncoded bool) matchSet {
	normalized, obfuscated := normalize(value)
	result := matchSet{categories: make(map[Category]bool), rules: make(map[string]bool), obfuscated: obfuscated}
	for _, candidate := range detectionRules {
		if candidate.pattern.MatchString(normalized) {
			result.categories[candidate.category] = true
			result.rules[candidate.id] = true
		}
	}
	if obfuscated && len(result.categories) > 0 {
		result.categories[Obfuscation] = true
		result.rules["unicode-or-control-obfuscation"] = true
	}
	if allowEncoded {
		for _, token := range base64Token.FindAllString(value, 8) {
			decoded, ok := decodeInstructionToken(token)
			if !ok {
				continue
			}
			nested := matchText(decoded, false)
			if !encodedFindingEligible(nested.categories) {
				continue
			}
			for category := range nested.categories {
				result.categories[category] = true
			}
			for ruleID := range nested.rules {
				result.rules["encoded:"+ruleID] = true
			}
			result.categories[EncodedInstructions] = true
			result.rules["base64-instruction-payload"] = true
		}
	}
	return result
}

func normalize(value string) (string, bool) {
	var builder strings.Builder
	builder.Grow(len(value))
	obfuscated := false
	for _, character := range value {
		switch {
		case character >= 0xFF01 && character <= 0xFF5E:
			character -= 0xFEE0
			obfuscated = true
		case character == '\u200b' || character == '\u200c' || character == '\u200d' || character == '\u2060' || character == '\ufeff' ||
			(character >= '\u202a' && character <= '\u202e') || (character >= '\u2066' && character <= '\u2069'):
			obfuscated = true
			continue
		case unicode.IsControl(character):
			if character != '\n' && character != '\r' && character != '\t' {
				obfuscated = true
			}
			character = ' '
		case unicode.IsSpace(character):
			character = ' '
		}
		builder.WriteRune(unicode.ToLower(character))
	}
	return joinSpacedLetters(strings.Join(strings.Fields(builder.String()), " ")), obfuscated
}

func joinSpacedLetters(value string) string {
	fields := strings.Fields(value)
	result := make([]string, 0, len(fields))
	for index := 0; index < len(fields); {
		end := index
		for end < len(fields) && utf8.RuneCountInString(strings.Trim(fields[end], ",.;:!?")) == 1 {
			end++
		}
		if end-index >= 4 {
			var word strings.Builder
			for _, field := range fields[index:end] {
				word.WriteString(strings.Trim(field, ",.;:!?"))
			}
			result = append(result, word.String())
			index = end
			continue
		}
		result = append(result, fields[index])
		index++
	}
	return strings.Join(result, " ")
}

func decodeInstructionToken(token string) (string, bool) {
	if len(token) > 4096 {
		return "", false
	}
	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		decoded, err = encoding.DecodeString(token)
		if err == nil {
			break
		}
	}
	if err != nil || len(decoded) < 12 || !utf8.Valid(decoded) || strings.IndexByte(string(decoded), 0) >= 0 {
		return "", false
	}
	printable := 0
	for _, character := range string(decoded) {
		if unicode.IsPrint(character) || unicode.IsSpace(character) {
			printable++
		}
	}
	return string(decoded), printable*10 >= utf8.RuneCount(decoded)*9
}

func encodedFindingEligible(categories map[Category]bool) bool {
	if categories[InstructionOverride] || categories[SecurityBypass] {
		return true
	}
	return (categories[CredentialAccess] || categories[EnvironmentExposure]) && categories[NetworkTransmission]
}

func classifySeverity(matches matchSet, kind SourceKind, text string) Severity {
	categories := matches.categories
	credential := categories[CredentialAccess] || categories[EnvironmentExposure]
	transmission := categories[NetworkTransmission]
	authority := categories[InstructionOverride] || categories[SecurityBypass] || categories[SecuritySettingChange]
	conceal := categories[Concealment]

	severity := Severity("")
	switch {
	case credential && transmission && (authority || conceal || categories[EncodedInstructions]):
		severity = Critical
	case credential && transmission, categories[InstructionOverride] && (categories[SecurityBypass] || credential || conceal), categories[SecurityBypass] && conceal:
		severity = High
	case categories[InstructionOverride], categories[SecurityBypass], categories[CredentialAccess], categories[EnvironmentExposure], categories[SecuritySettingChange]:
		severity = Medium
	case categories[AuthorityImpersonation] && (conceal || matches.obfuscated):
		severity = Medium
	case categories[Concealment]:
		severity = Medium
	case categories[AuthorityImpersonation], categories[Obfuscation]:
		severity = Low
	default:
		return ""
	}

	if kind != AgentInstructions && defensiveContext(text) {
		if severity.Rank() <= Medium.Rank() {
			return ""
		}
		return Medium
	}
	return severity
}

func defensiveContext(value string) bool {
	normalized, _ := normalize(value)
	shadowExample := strings.Contains(normalized, "shadow resource") && strings.Contains(normalized, ".aws/credentials")
	markers := len(defensiveLanguage.FindAllString(normalized, 3))
	return shadowExample || explicitDefense.MatchString(normalized) || negativeExposure.MatchString(normalized) || markers >= 2
}

func sortedCategories(values map[Category]bool) []Category {
	result := make([]Category, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func sortedRules(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
