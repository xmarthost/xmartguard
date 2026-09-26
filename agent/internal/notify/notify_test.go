package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChat(t *testing.T) {
	var slack, tg map[string]any
	var tgPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.URL.Path, "/bot") {
			tgPath = r.URL.Path
			json.Unmarshal(body, &tg)
		} else {
			json.Unmarshal(body, &slack)
		}
	}))
	defer srv.Close()
	TelegramURL = srv.URL
	err := Chat(Channels{SlackWebhook: srv.URL + "/hook", TelegramToken: "123:abc", TelegramChat: "-100"}, "subj", "body")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(slack["text"].(string), "subj") || tg["chat_id"] != "-100" || tgPath != "/bot123:abc/sendMessage" {
		t.Fatalf("slack %v tg %v %s", slack, tg, tgPath)
	}
}
