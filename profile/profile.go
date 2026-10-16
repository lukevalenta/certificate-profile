package profile

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Document struct {
	Type        string                    `json:"type"`
	Name        string                    `json:"name"`
	Version     string                    `json:"version"`
	Description string                    `json:"description"`
	Org         string                    `json:"org"`
	Spec        string                    `json:"spec"`
	Includes    []string                  `json:"$includes"`
	Definitions map[string]map[string]any `json:"$defs"`
	Content     Content                   `json:"content"`
}

type Content struct {
	Version    *IntegerRule             `json:"version"`
	Subject    *NameRule                `json:"subject"`
	Extensions map[string]ExtensionRule `json:"extensions"`
}

type IntegerRule struct {
	AlwaysPresent *bool `json:"alwaysPresent"`
	ValueEq       *int  `json:"valueEq"`
}

type NameRule struct {
	RDNs []RDNRule `json:"rdns"`
}

type RDNRule struct {
	CommonName *StringRule `json:"commonName"`
}

type StringRule struct {
	AlwaysPresent *bool   `json:"alwaysPresent"`
	ValueEq       *string `json:"valueEq"`
	ValueMatch    *string `json:"valueMatch"`
}

type ExtensionRule struct {
	AlwaysPresent *bool        `json:"alwaysPresent"`
	Critical      *bool        `json:"critical"`
	Values        []StringRule `json:"values"`
}

type Finding struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (d Document) Validate() error {
	if d.Type != "certificate" {
		return fmt.Errorf("type must be certificate")
	}
	if d.Name == "" {
		return fmt.Errorf("name is required")
	}
	if d.Version == "" {
		return fmt.Errorf("version is required")
	}
	if d.Content.Version != nil && d.Content.Version.ValueEq != nil && *d.Content.Version.ValueEq < 0 {
		return fmt.Errorf("content.version.valueEq must be non-negative")
	}
	if d.Content.Subject != nil {
		for i, rdn := range d.Content.Subject.RDNs {
			if rdn.CommonName == nil {
				return fmt.Errorf("content.subject.rdns[%d] must define commonName", i)
			}
			if err := rdn.CommonName.validate(fmt.Sprintf("content.subject.rdns[%d].commonName", i)); err != nil {
				return err
			}
		}
	}
	for name, rule := range d.Content.Extensions {
		if _, ok := extensionNames[name]; !ok {
			return fmt.Errorf("unsupported extension %q", name)
		}
		for i := range rule.Values {
			if err := rule.Values[i].validate(fmt.Sprintf("content.extensions.%s.values[%d]", name, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r StringRule) validate(path string) error {
	if r.ValueMatch != nil {
		if _, err := regexp.Compile(*r.ValueMatch); err != nil {
			return fmt.Errorf("%s.valueMatch: %w", path, err)
		}
	}
	return nil
}

func (d Document) Check(cert *x509.Certificate) []Finding {
	var findings []Finding
	if rule := d.Content.Version; rule != nil {
		if rule.AlwaysPresent != nil && !*rule.AlwaysPresent {
			findings = append(findings, finding("content.version.alwaysPresent", "unsupported-rule", "certificate version is always present"))
		}
		if rule.ValueEq != nil && cert.Version != *rule.ValueEq {
			findings = append(findings, finding("content.version.valueEq", "value-mismatch", fmt.Sprintf("value is %d, profile requires %d", cert.Version, *rule.ValueEq)))
		}
	}
	if d.Content.Subject != nil {
		findings = append(findings, checkSubject(cert, *d.Content.Subject)...)
	}
	return append(findings, d.checkExtensions(cert)...)
}

var extensionNames = map[string]string{
	"authorityInformationAccess":     "1.3.6.1.5.5.7.1.1",
	"authorityKeyIdentifier":         "2.5.29.35",
	"basicConstraints":               "2.5.29.19",
	"certificatePolicies":            "2.5.29.32",
	"crlDistributionPoints":          "2.5.29.31",
	"extendedKeyUsage":               "2.5.29.37",
	"keyUsage":                       "2.5.29.15",
	"signedCertificateTimestampList": "1.3.6.1.4.1.11129.2.4.2",
	"subjectAltName":                 "2.5.29.17",
	"subjectKeyIdentifier":           "2.5.29.14",
}

func (d Document) checkExtensions(cert *x509.Certificate) []Finding {
	var findings []Finding
	present := make(map[string]bool, len(cert.Extensions))
	for _, extension := range cert.Extensions {
		present[extension.Id.String()] = extension.Critical
	}
	var names []string
	for name := range d.Content.Extensions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rule := d.Content.Extensions[name]
		critical, ok := present[extensionNames[name]]
		required := rule.AlwaysPresent == nil || *rule.AlwaysPresent
		if required && !ok {
			findings = append(findings, finding("content.extensions."+name, "required-absent", "required extension is absent"))
			continue
		}
		if ok && rule.Critical != nil && critical != *rule.Critical {
			findings = append(findings, finding("content.extensions."+name+".critical", "value-mismatch", fmt.Sprintf("critical is %t, profile requires %t", critical, *rule.Critical)))
		}
	}
	var oids []string
	for oid := range present {
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	for _, oid := range oids {
		name, known := extensionName(oid)
		if !known {
			findings = append(findings, finding("content.extensions", "unsupported-extension", "certificate contains unsupported extension "+oid))
			continue
		}
		if _, documented := d.Content.Extensions[name]; !documented {
			findings = append(findings, finding("content.extensions", "undocumented-extension", "certificate contains undocumented extension "+oid))
		}
	}
	return findings
}

func extensionName(oid string) (string, bool) {
	for name, knownOID := range extensionNames {
		if oid == knownOID {
			return name, true
		}
	}
	return "", false
}

func checkSubject(cert *x509.Certificate, rule NameRule) []Finding {
	var findings []Finding
	if len(cert.Subject.Names) != len(rule.RDNs) {
		return append(findings, finding("content.subject", "attribute-count-mismatch", fmt.Sprintf("contains %d attributes, profile describes %d", len(cert.Subject.Names), len(rule.RDNs))))
	}
	for i, rdn := range rule.RDNs {
		path := fmt.Sprintf("content.subject.rdns[%d].commonName", i)
		if rdn.CommonName == nil {
			findings = append(findings, finding(path, "unsupported-rule", "profile does not define commonName"))
			continue
		}
		actual := cert.Subject.Names[i]
		if actual.Type.String() != "2.5.4.3" {
			findings = append(findings, finding(path, "attribute-mismatch", "attribute is not commonName"))
			continue
		}
		value, ok := actual.Value.(string)
		if !ok {
			findings = append(findings, finding(path, "type-mismatch", "value is not a string"))
			continue
		}
		if rdn.CommonName.ValueEq != nil && value != *rdn.CommonName.ValueEq {
			findings = append(findings, finding(path+".valueEq", "value-mismatch", fmt.Sprintf("value is %q, profile requires %q", value, *rdn.CommonName.ValueEq)))
		}
		if rdn.CommonName.ValueMatch != nil {
			matched, _ := regexp.MatchString(*rdn.CommonName.ValueMatch, value)
			if !matched {
				findings = append(findings, finding(path+".valueMatch", "value-mismatch", fmt.Sprintf("value %q does not match %q", value, *rdn.CommonName.ValueMatch)))
			}
		}
	}
	return findings
}

func finding(path, code, message string) Finding {
	return Finding{Path: path, Code: code, Message: message}
}

func (d Document) Markdown() string {
	var lines []string
	lines = append(lines, "# "+d.Name, "", "Version: `"+d.Version+"`")
	if d.Description != "" {
		lines = append(lines, "", d.Description)
	}
	if d.Org != "" {
		lines = append(lines, "", "Organization: `"+d.Org+"`")
	}
	if d.Spec != "" {
		lines = append(lines, "", "Specification: `"+d.Spec+"`")
	}
	lines = append(lines, "", "## Certificate profile")
	if d.Content.Version != nil && d.Content.Version.ValueEq != nil {
		lines = append(lines, "", "- Certificate version: "+fmt.Sprint(*d.Content.Version.ValueEq))
	}
	if d.Content.Subject != nil {
		for _, rdn := range d.Content.Subject.RDNs {
			if rdn.CommonName != nil {
				lines = append(lines, "- Subject commonName: "+stringRuleMarkdown(*rdn.CommonName))
			}
		}
	}
	var names []string
	for name := range d.Content.Extensions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rule := d.Content.Extensions[name]
		presence := "MUST"
		if rule.AlwaysPresent != nil && !*rule.AlwaysPresent {
			presence = "MAY"
		}
		line := "- `" + name + "`: " + presence
		if rule.Critical != nil {
			line += fmt.Sprintf(", critical: %t", *rule.Critical)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
}

func stringRuleMarkdown(rule StringRule) string {
	var constraints []string
	if rule.ValueEq != nil {
		constraints = append(constraints, "equals `"+*rule.ValueEq+"`")
	}
	if rule.ValueMatch != nil {
		constraints = append(constraints, "matches `"+*rule.ValueMatch+"`")
	}
	if len(constraints) == 0 {
		return "any value"
	}
	return strings.Join(constraints, ", ")
}
