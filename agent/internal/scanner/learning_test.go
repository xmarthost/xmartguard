package scanner

import "testing"

// From the AI Learning export (2026-10-15).
func TestBackupArchivesAreNotOpened(t *testing.T) {
	for _, p := range []string{
		"/home/u/public_html/wp-content/updraft/backup_2026-10-12-1325_Site_eaed9614365e-plugins2.zip",
		"/home/u/site.us/insurance/wp-content/backup-migration-gl4VOsuhBz/backups/BM_2026-10-12_11_28_20_x.zip",
		"/home/u/site.com/wp-content/ai1wm-backups/site-20261012.zip",
	} {
		if !backupArchive(p) {
			t.Errorf("%s opened", p)
		}
	}
	for _, p := range []string{
		"/home/u/public_html/wp-content/uploads/2026/10/bd-60c11765f07a.zip",
		"/home/u/public_html/index.zip",
		"/home/u/site.com/wp-content/backup-migration-x/other.zip",
	} {
		if backupArchive(p) {
			t.Errorf("%s skipped", p)
		}
	}
}

func TestFingerprintJSIsNotAMiner(t *testing.T) {
	fp := []byte(`!function(e){var t=new Client.Init({token:"x"});t.get()}(window);`)
	if v := analyzeJS(fp); v != nil && v.signature == "JS.Miner.Browser" {
		t.Fatal("FingerprintJS-style client flagged as a miner")
	}
	miner := []byte(`var m = new CoinHive.Anonymous('KEY'); m.start();`)
	if v := analyzeJS(miner); v == nil || v.signature != "JS.Miner.Browser" {
		t.Fatal("CoinHive miner not flagged")
	}
}
