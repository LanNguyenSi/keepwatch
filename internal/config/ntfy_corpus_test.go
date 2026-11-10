package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

// The property that install and doctor rely on: a configuration that Load
// accepts is one that notify.NewNtfy accepts. Otherwise a host would pass
// "config check", get its services installed with --notify, and then exit 3 on
// every scheduled run.
func TestLoadAcceptsOnlyWhatNewNtfyAccepts(t *testing.T) {
	schemes := []string{"https", "http", "ftp", ""}
	hosts := []string{"example.com", "127.0.0.1", "localhost", "[::1]", "10.0.0.1", "", "exa mple.com"}
	ports := []string{"", ":0", ":80", ":65535", ":65536", ":99999", ":", ":abc"}
	users := []string{"", "u@", "u:p@"}
	tails := []string{"", "/x", "/%zz", "?a=b", "#f", "?#", "/x/?q"}
	topics := []string{"alerts", "kw.alerts", "", "a b", "a/b", "ü", strings.Repeat("a", 64), strings.Repeat("a", 65), "-_", "a?b", "a#b"}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "keepwatch.yaml")
	accepted, rejected := 0, 0
	try := func(url, topic string) {
		t.Helper()
		doc := fmt.Sprintf("notify:\n  ntfy:\n    url: %q\n    topic: %q\n", url, topic)
		if err := os.WriteFile(file, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(file)
		if err != nil {
			rejected++
			for _, secret := range []string{"u:p", "u@", "%zz", "a=b"} {
				if strings.Contains(url, secret) && strings.Contains(err.Error(), secret) {
					t.Errorf("url %q: the error holds %q: %v", url, secret, err)
				}
			}
			return
		}
		accepted++
		n := cfg.Notify.Ntfy
		if n == nil {
			t.Fatalf("url %q topic %q: loaded without notify.ntfy", url, topic)
		}
		if _, nerr := notify.NewNtfy(notify.NtfyConfig{URL: n.URL, Topic: n.Topic}); nerr != nil {
			t.Errorf("Load accepts url %q topic %q, but NewNtfy refuses it: %v", url, topic, nerr)
		}
	}
	for _, sc := range schemes {
		for _, h := range hosts {
			for _, po := range ports {
				for _, us := range users {
					for _, ta := range tails {
						try(sc+"://"+us+h+po+ta, "alerts")
					}
				}
			}
		}
	}
	for _, tp := range topics {
		try("https://example.com", tp)
		try("http://127.0.0.1:8080/ntfy", tp)
	}
	// The corpus must contain both kinds, or it proves nothing.
	if accepted < 40 || rejected < 1000 {
		t.Errorf("corpus accepted %d, rejected %d", accepted, rejected)
	}
	t.Logf("corpus: %d accepted, %d rejected", accepted, rejected)
}
