package verify

import (
	"bufio"
	"os"
	"strings"
)

// maxPairScanBytes bounds how much of a file is read looking for the other
// half of a credential. A credentials file is small; anything large is not
// one, and a scanner should not load an arbitrary file into memory.
const maxPairScanBytes = 256 << 10

// PairAWSCredential recovers a complete AWS credential from the file a
// detection came from.
//
// AWS is the one provider whose verification needs two values, and secret
// scanners report one match per line. The access key ID on its own is low
// entropy, so detectors frequently skip it entirely and report only the
// secret access key -- leaving neither half verifiable despite both sitting
// in the same file, which is exactly how AWS credentials leak.
//
// So when a detection lands in a file, that file is scanned for the matching
// half. Only AWS-shaped tokens are extracted, only from the file the finding
// already pointed at, and the values are returned to the caller to use and
// drop. Nothing is stored, and nothing is read from anywhere the scanner was
// not already looking.
func PairAWSCredential(path, detected string) (combined string, ok bool) {
	// The detection may already contain both halves.
	if _, _, complete := splitAWSCredential(detected); complete {
		return detected, true
	}
	if path == "" {
		return "", false
	}

	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil || st.IsDir() || st.Size() > maxPairScanBytes {
		return "", false
	}

	var keyID, secretKey string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		for _, tok := range tokenize(sc.Text()) {
			switch {
			case keyID == "" && isAWSKeyID(tok):
				keyID = tok
			case secretKey == "" && isAWSSecretKey(tok):
				secretKey = tok
			}
		}
		if keyID != "" && secretKey != "" {
			break
		}
	}

	// The detected value is the more reliable half when it fits the shape.
	if isAWSSecretKey(strings.TrimSpace(detected)) {
		secretKey = strings.TrimSpace(detected)
	}
	if isAWSKeyID(strings.TrimSpace(detected)) {
		keyID = strings.TrimSpace(detected)
	}

	if keyID == "" || secretKey == "" {
		return "", false
	}
	return keyID + " " + secretKey, true
}

// FileMentionsAWSKey reports whether a file contains an AWS access key ID,
// used to decide whether pairing is worth attempting at all.
func FileMentionsAWSKey(path string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxPairScanBytes {
		return false
	}
	return strings.Contains(string(data), "AKIA") || strings.Contains(string(data), "ASIA")
}

func tokenize(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '"', '\'', ',', '=', ':', ';', '(', ')', '[', ']', '{', '}', '\n', '\r':
			return true
		}
		return false
	})
}

func isAWSKeyID(s string) bool {
	return len(s) == 20 && (strings.HasPrefix(s, "AKIA") || strings.HasPrefix(s, "ASIA"))
}

// isAWSSecretKey matches the shape of a secret access key: 40 characters from
// the base64 alphabet. Shape is all that can be checked locally; whether it is
// real is what the STS call is for.
func isAWSSecretKey(s string) bool {
	return len(s) == 40 && isBase64ish(s)
}
