package profile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func boolPtr(value bool) *bool       { return &value }
func intPtr(value int) *int          { return &value }
func stringPtr(value string) *string { return &value }

func TestLoadFileJSON5IncludesAndMetadata(t *testing.T) {
	directory := t.TempDir()
	writeProfile(t, directory, "base.json5", `{
		$defs: {base: {type: 'string'}},
	}`)
	writeProfile(t, directory, "profile.json5", `{
		type: 'certificate',
		name: 'edge',
		version: '1.0',
		description: 'test profile',
		org: 'Cloudflare',
		spec: 'infrared/v1',
		$includes: ['base.json5'],
		$defs: {local: {type: 'integer'}},
		content: {
			version: {valueEq: 3},
			subject: {rdns: [{commonName: {valueEq: 'example.com'}}]},
			extensions: {basicConstraints: {alwaysPresent: true, critical: true}},
		},
	}`)

	document, err := LoadFile(filepath.Join(directory, "profile.json5"))
	if err != nil {
		t.Fatal(err)
	}
	if document.Org != "Cloudflare" || document.Spec != "infrared/v1" {
		t.Fatalf("metadata = %#v", document)
	}
	if !reflect.DeepEqual(document.Definitions["base"], map[string]any{"type": "string"}) {
		t.Fatalf("merged definitions = %#v", document.Definitions)
	}
	markdown := document.Markdown()
	for _, want := range []string{"# edge", "Organization: `Cloudflare`", "Specification: `infrared/v1`", "Certificate version: 3", "Subject commonName: equals `example.com`", "`basicConstraints`: MUST, critical: true"} {
		if !strings.Contains(markdown, want) {
			t.Errorf("Markdown() missing %q:\n%s", want, markdown)
		}
	}
}

func TestLoadFileRejectsInvalidProfiles(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		profile string
		want    string
	}{
		{name: "missing metadata", profile: `{type: 'certificate', name: 'name'}`, want: "version is required"},
		{name: "wrong type", profile: `{type: 'key', name: 'name', version: '1'}`, want: "type must be certificate"},
		{name: "unsupported extension", profile: `{type: 'certificate', name: 'name', version: '1', content: {extensions: {foo: {}}}}`, want: `unsupported extension "foo"`},
		{name: "invalid expression", profile: `{type: 'certificate', name: 'name', version: '1', content: {subject: {rdns: [{commonName: {valueMatch: '['}}]}}}`, want: "error parsing regexp"},
		{name: "absolute include", profile: `{type: 'certificate', name: 'name', version: '1', $includes: ['/tmp/base.json5']}`, want: "must be relative"},
		{name: "duplicate definition", files: map[string]string{"base.json5": `{$defs: {shared: {}}}`}, profile: `{type: 'certificate', name: 'name', version: '1', $defs: {shared: {}}, $includes: ['base.json5']}`, want: `duplicate definition "shared"`},
		{name: "cycle", files: map[string]string{"base.json5": `{$includes: ['profile.json5']}`}, profile: `{type: 'certificate', name: 'name', version: '1', $includes: ['base.json5']}`, want: "include cycle"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			for name, contents := range test.files {
				writeProfile(t, directory, name, contents)
			}
			path := writeProfile(t, directory, "profile.json5", test.profile)
			_, err := LoadFile(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadFile() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	document := Document{
		Type: "certificate", Name: "test", Version: "1",
		Content: Content{
			Version: &IntegerRule{ValueEq: intPtr(3)},
			Subject: &NameRule{RDNs: []RDNRule{{CommonName: &StringRule{ValueEq: stringPtr("example.com"), ValueMatch: stringPtr(`^www\.`)}}}},
			Extensions: map[string]ExtensionRule{
				"basicConstraints": {AlwaysPresent: boolPtr(true), Critical: boolPtr(true)},
				"keyUsage":         {AlwaysPresent: boolPtr(false)},
			},
		},
	}
	certificate := &x509.Certificate{
		Version: 2,
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.com"}}},
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: false},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}},
			{Id: asn1.ObjectIdentifier{1, 2, 3}},
		},
	}
	findings := document.Check(certificate)
	want := []Finding{
		{Path: "content.version.valueEq", Code: "value-mismatch", Message: "value is 2, profile requires 3"},
		{Path: "content.subject.rdns[0].commonName.valueMatch", Code: "value-mismatch", Message: `value "example.com" does not match "^www\\."`},
		{Path: "content.extensions.basicConstraints.critical", Code: "value-mismatch", Message: "critical is false, profile requires true"},
		{Path: "content.extensions", Code: "unsupported-extension", Message: "certificate contains unsupported extension 1.2.3"},
		{Path: "content.extensions", Code: "undocumented-extension", Message: "certificate contains undocumented extension 2.5.29.17"},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("Check() = %#v, want %#v", findings, want)
	}
}

func TestCheckSubjectAndExtensionPresence(t *testing.T) {
	document := Document{Type: "certificate", Name: "test", Version: "1", Content: Content{
		Subject:    &NameRule{RDNs: []RDNRule{{CommonName: &StringRule{}}}},
		Extensions: map[string]ExtensionRule{"basicConstraints": {AlwaysPresent: boolPtr(true)}},
	}}
	findings := document.Check(&x509.Certificate{Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Cloudflare"}}}})
	want := []Finding{
		{Path: "content.subject.rdns[0].commonName", Code: "attribute-mismatch", Message: "attribute is not commonName"},
		{Path: "content.extensions.basicConstraints", Code: "required-absent", Message: "required extension is absent"},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("Check() = %#v, want %#v", findings, want)
	}
}

func writeProfile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
