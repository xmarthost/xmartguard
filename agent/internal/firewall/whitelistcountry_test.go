package firewall

import (
	"fmt"
	"reflect"
	"testing"
)

func TestWithoutRanges(t *testing.T) {
	networks := []string{"139.135.0.0/16", "58.27.128.0/17", "2400:adc0::/32", "182.176.0.0/12", "182.176.0.0/16"}
	entries := []string{"139.135.60.46", "58.27.210.138", "58.27.10.1", "2400:adc0:1::5", "182.180.1.0/24", "8.8.8.8", "2001:db8::1", "bad"}
	got := withoutRanges(entries, networks)
	want := []string{"58.27.10.1", "8.8.8.8", "2001:db8::1", "bad"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := withoutRanges(entries, nil); len(got) != len(entries) {
		t.Fatal("no networks: nothing dropped")
	}
}

// 150,000 entries against a country of 1,000 networks stays fast.
func BenchmarkWithoutRanges(b *testing.B) {
	var nets, entries []string
	for i := 0; i < 1000; i++ {
		nets = append(nets, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	for i := 0; i < 150000; i++ {
		entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", 1+i%200, (i/200)%256, i%256, 7))
	}
	for i := 0; i < b.N; i++ {
		withoutRanges(entries, nets)
	}
}
