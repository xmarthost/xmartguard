package cms

import (
	"context"
	"os"
	"testing"
	"time"
)

// DBChangedSince on a real MariaDB/MySQL (XG_MYSQL_TEST=user:pass@db):
// unchanged tables keep the last result, a new post is a change.
func TestDBChangedSinceMySQL(t *testing.T) {
	if os.Getenv("XG_MYSQL_TEST") == "" {
		t.Skip("set XG_MYSQL_TEST=1 with the wpt database (see the commit)")
	}
	c := DBConfig{Name: "wpt", User: "wpu", Password: "wpPass_123", Host: "localhost", Prefix: "wp_"}
	ctx := context.Background()
	time.Sleep(1100 * time.Millisecond)
	checked := time.Now().Unix()
	time.Sleep(1100 * time.Millisecond)
	if changed, ok := DBChangedSince(ctx, c, checked); !ok || changed {
		t.Fatalf("untouched tables: changed=%v ok=%v", changed, ok)
	}
	db, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO wp_posts (post_content) VALUES ('hello')`); err != nil {
		t.Fatal(err)
	}
	if changed, ok := DBChangedSince(ctx, c, checked); !ok || !changed {
		t.Fatalf("new post: changed=%v ok=%v", changed, ok)
	}
}
