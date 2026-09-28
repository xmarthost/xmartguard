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

// Admin alerts reach Telegram even when no admin email is set (this used
// to drop them: only email-queued alerts went to chat).
func TestAdminAlertWithoutEmail(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		got <- r.URL.Path + " " + m["text"].(string)
	}))
	defer srv.Close()
	TelegramURL = srv.URL
	Sendmail = "/nonexistent/sendmail"
	m := &Mailer{Hostname: "h1", Admin: func() string { return "" },
		Channels: func() Channels { return Channels{TelegramToken: " bot123:abc ", TelegramChat: " 42 "} }}
	m.EnqueueAdmin("malware detected", "file x")
	m.EnqueueAdmin("malware detected", "file y")
	m.Flush()
	select {
	case s := <-got:
		if !strings.HasPrefix(s, "/bot123:abc/sendMessage ") || !strings.Contains(s, "(+1 more)") || !strings.Contains(s, "file y") {
			t.Fatal(s)
		}
	default:
		t.Fatal("nothing sent to Telegram")
	}
}

func TestTelegramErrorExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()
	TelegramURL = srv.URL
	err := Chat(Channels{TelegramToken: "1:a", TelegramChat: "5"}, "s", "b")
	if err == nil || !strings.Contains(err.Error(), "chat not found") || !strings.Contains(err.Error(), "/start") {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"123:abc": "123:abc", " bot123:abc\n": "123:abc", "https://api.telegram.org/bot123:abc/getUpdates": "123:abc"} {
		if TelegramToken(in) != want {
			t.Fatalf("%q -> %q", in, TelegramToken(in))
		}
	}
}
