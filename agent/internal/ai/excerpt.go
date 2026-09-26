package ai

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The excerpt is what an AI API sees of a file. It is built to use as few
// tokens as possible without hiding what matters:
//
//   - every line keeps its number ("12|code") so the AI can point at the
//     injected lines, which Trim then removes;
//   - indentation and blank lines are dropped;
//   - long encoded strings (base64, hex, packed JavaScript) are shortened to
//     their first characters plus their length: the AI judges what the code
//     does with them, not the payload itself;
//   - when the file is still too big, the beginning and end of the file and
//     the lines around risky calls are kept, the rest is summarised as
//     "… N lines …".

var (
	longToken = regexp.MustCompile(`[A-Za-z0-9+/=_\\%-]{160,}`)
	hotRe     = regexp.MustCompile(`(?i)\b(?:eval|assert|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|create_function|` +
		`shell_exec|passthru|proc_open|popen|pcntl_exec|system|exec|move_uploaded_file|file_put_contents|fwrite|fsockopen|` +
		`curl_exec|curl_init|wp_insert_user|wp_create_user|add_user|mail|unserialize|extract|call_user_func(?:_array)?|` +
		`preg_replace|include|require|atob|fromCharCode|unescape|document\.write|setcookie|header)\s*\(|` +
		`\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b|\\x[0-9a-f]{2}|\$\{?\$?\w+\}?\s*\(|<iframe|<script|` +
		`display\s*:\s*none|http_user_agent|googlebot|php://input|chmod\s*\(|\bchr\s*\(`)
)

const (
	maxLine  = 360 // characters kept of one line (long minified lines)
	headKeep = 25  // lines always kept from the top
	tailKeep = 8   // lines always kept from the bottom
	window   = 5   // lines kept around a risky line
)

type exLine struct {
	no   int
	text string
	hot  int
}

func shorten(line string) string {
	line = longToken.ReplaceAllStringFunc(line, func(t string) string {
		return t[:48] + "…[" + strconv.Itoa(len(t)) + " chars]"
	})
	if len(line) <= maxLine {
		return line
	}
	// Keep the start, the first risky call and the end of a long line.
	parts := []string{safeCut(line, 0, 200)}
	if loc := hotRe.FindStringIndex(line[200:]); loc != nil {
		at := 200 + loc[0]
		parts = append(parts, safeCut(line, max(200, at-60), at+100))
	}
	parts = append(parts, safeCut(line, len(line)-60, len(line)))
	return strings.Join(parts, " … ") + fmt.Sprintf(" …[line has %d chars]", len(line))
}

// safeCut slices s[a:b] on UTF-8 boundaries.
func safeCut(s string, a, b int) string {
	a, b = max(0, a), min(len(s), b)
	for a < b && !utf8.RuneStart(s[a]) {
		a++
	}
	for b < len(s) && b > a && !utf8.RuneStart(s[b]) {
		b--
	}
	return s[a:b]
}

// Excerpt returns the compact, line-numbered text sent for a file, the
// number of lines in the file and whether parts were left out.
func Excerpt(raw []byte, budget int) (string, int, bool) {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	all := strings.Split(strings.ToValidUTF8(string(raw), "?"), "\n")
	var lines []exLine
	size := 0
	for i, l := range all {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		t = shorten(t)
		e := exLine{no: i + 1, text: t, hot: len(hotRe.FindAllStringIndex(t, 8))}
		lines = append(lines, e)
		size += len(t) + 6
	}
	if size <= budget {
		return render(lines, nil), len(all), false
	}

	keep := make([]bool, len(lines))
	used := 0
	take := func(i int) {
		if i >= 0 && i < len(lines) && !keep[i] && used+len(lines[i].text)+6 <= budget {
			keep[i] = true
			used += len(lines[i].text) + 6
		}
	}
	for i := 0; i < headKeep && i < len(lines); i++ {
		take(i)
	}
	for i := len(lines) - tailKeep; i < len(lines); i++ {
		take(i)
	}
	hot := []int{}
	for i, l := range lines {
		if l.hot > 0 {
			hot = append(hot, i)
		}
	}
	sort.SliceStable(hot, func(a, b int) bool { return lines[hot[a]].hot > lines[hot[b]].hot })
	for _, i := range hot {
		take(i)
		for d := 1; d <= window; d++ {
			take(i - d)
			take(i + d)
		}
		if used >= budget {
			break
		}
	}
	return render(lines, keep), len(all), true
}

func render(lines []exLine, keep []bool) string {
	var b strings.Builder
	prev := -1
	for i, l := range lines {
		if keep != nil && !keep[i] {
			continue
		}
		if i > prev+1 {
			fmt.Fprintf(&b, "… %d lines …\n", i-prev-1)
		}
		b.WriteString(strconv.Itoa(l.no))
		b.WriteByte('|')
		b.WriteString(l.text)
		b.WriteByte('\n')
		prev = i
	}
	if prev < len(lines)-1 {
		fmt.Fprintf(&b, "… %d lines …\n", len(lines)-1-prev)
	}
	return b.String()
}
