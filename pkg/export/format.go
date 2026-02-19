package export

import (
	"encoding/json"
	"fmt"
	"os"
)

// WriteJSON writes the bundle as JSON to the specified file path.
func WriteJSON(bundle *Bundle, path string) error {
	data, err := bundle.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing bundle file: %w", err)
	}
	return nil
}

// ReadJSON reads a bundle from a JSON file.
func ReadJSON(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bundle file: %w", err)
	}
	return Unmarshal(data)
}

// FormatRecordSummary returns a one-line summary of a bundle record.
func FormatRecordSummary(rec BundleRecord) string {
	payload, err := json.Marshal(rec.Envelope)
	if err != nil {
		return fmt.Sprintf("seq=%d (error reading envelope)", rec.SequenceNumber)
	}
	_ = payload
	return fmt.Sprintf("seq=%d sigs=%d", rec.SequenceNumber, len(rec.Envelope.Signatures))
}
