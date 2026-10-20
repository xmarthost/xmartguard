package core

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Audit A1 F8 / A10 F3: every secret-looking settings value (key, token,
// secret, password, webhook) is masked for the portal and kept on save.
func TestEverySecretFieldIsMasked(t *testing.T) {
	secretName := regexp.MustCompile(`key|token|secret|password|webhook`)
	public := map[string]bool{"captcha.site_key": true} // shown to visitors anyway
	const value = "inert0secret0value0for0tests"
	var s settings.Settings
	sv := reflect.ValueOf(&s).Elem()
	var names []string
	for i := 0; i < sv.NumField(); i++ {
		if sv.Field(i).Kind() != reflect.Struct {
			continue
		}
		section := strings.Split(sv.Type().Field(i).Tag.Get("json"), ",")[0]
		st := sv.Field(i)
		for j := 0; j < st.NumField(); j++ {
			name := strings.Split(st.Type().Field(j).Tag.Get("json"), ",")[0]
			full := section + "." + name
			if st.Field(j).Kind() != reflect.String || !secretName.MatchString(name) || public[full] {
				continue
			}
			st.Field(j).SetString(value)
			names = append(names, full)
		}
	}
	if len(names) < 6 {
		t.Fatalf("found only %v", names)
	}
	out, _ := json.Marshal(masked(s))
	if strings.Contains(string(out), value) {
		t.Fatalf("a secret is sent in full; fields checked: %v", names)
	}
	// Each one is in secretFields, so a masked value sent back keeps the key.
	listed := map[string]bool{}
	for _, f := range secretFields {
		listed[f[0]+"."+f[1]] = true
	}
	for _, n := range names {
		if !listed[n] {
			t.Errorf("%s missing from secretFields", n)
		}
	}
	back := keepSecrets(json.RawMessage(`{"reputation":{"spamhaus_dqs_key":"********alue"}}`), s)
	if strings.Contains(string(back), "spamhaus_dqs_key") {
		t.Fatalf("masked value would overwrite the key: %s", back)
	}
}
