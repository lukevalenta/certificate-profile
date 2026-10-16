package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/titanous/json5"
)

func LoadFile(path string) (Document, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return Document{}, fmt.Errorf("resolving profile path: %w", err)
	}
	document, err := loadDocument(path, make(map[string]bool))
	if err != nil {
		return Document{}, err
	}
	if err := document.Validate(); err != nil {
		return Document{}, fmt.Errorf("validating profile: %w", err)
	}
	return document, nil
}

func loadDocument(path string, stack map[string]bool) (Document, error) {
	path = filepath.Clean(path)
	if stack[path] {
		return Document{}, fmt.Errorf("profile include cycle at %q", path)
	}
	stack[path] = true
	defer delete(stack, path)

	contents, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("reading profile %q: %w", path, err)
	}
	var document Document
	if err := json5.Unmarshal(contents, &document); err != nil {
		return Document{}, fmt.Errorf("parsing profile %q: %w", path, err)
	}
	for _, include := range document.Includes {
		if filepath.IsAbs(include) {
			return Document{}, fmt.Errorf("included profile %q must be relative", include)
		}
		included, err := loadDocument(filepath.Join(filepath.Dir(path), include), stack)
		if err != nil {
			return Document{}, err
		}
		if err := mergeDefinitions(&document, included); err != nil {
			return Document{}, err
		}
	}
	return document, nil
}

func mergeDefinitions(document *Document, included Document) error {
	if len(included.Definitions) == 0 {
		return nil
	}
	if document.Definitions == nil {
		document.Definitions = make(map[string]map[string]any)
	}
	for name, definition := range included.Definitions {
		if _, exists := document.Definitions[name]; exists {
			return fmt.Errorf("duplicate definition %q", name)
		}
		document.Definitions[name] = definition
	}
	return nil
}
