package ml

import (
	"bytes"
	"math"
	"strconv"
)

// Features returns the distinct hashed feature indices of content.
func Features(content []byte) []uint32 {
	seen := make(map[uint32]struct{}, 256)
	out := make([]uint32, 0, 256)
	forEachFeature(content, func(name string) {
		i := hash(name)
		if _, ok := seen[i]; !ok {
			seen[i] = struct{}{}
			out = append(out, i)
		}
	})
	return out
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c|0x20) >= 'a' && (c|0x20) <= 'z'
}

func isIdent(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

func bucket(n int) string {
	if n <= 0 {
		return "0"
	}
	return strconv.Itoa(int(math.Log2(float64(n))) + 1)
}

// forEachFeature calls fn for every feature name in content:
//
//   - identifiers (lower-cased, variables collapsed to "$" except PHP
//     superglobals), marked "c:" when called like a function;
//   - bigrams of consecutive identifiers (catches call chains such as a
//     decoder nested inside an evaluator);
//   - structural measurements bucketed on a log scale: size, longest line,
//     escapes, long unbroken strings, variable-function calls, PHP tags,
//     non-ASCII density and byte entropy.
func forEachFeature(content []byte, fn func(string)) {
	if len(content) > MaxBytes {
		content = content[:MaxBytes]
	}
	var prev string
	var hexEsc, longRuns, varCalls, phpTags, nonASCII, lines, maxLine, lineLen, run int
	var counts [256]int
	n := len(content)
	for i := 0; i < n; {
		c := content[i]
		counts[c]++
		if c >= 0x80 {
			nonASCII++
		}
		if c == '\n' {
			lines++
			if lineLen > maxLine {
				maxLine = lineLen
			}
			lineLen = 0
		} else {
			lineLen++
		}
		if c > ' ' && c != '"' && c != '\'' && c != ';' && c != ',' && c != '(' && c != ')' {
			run++
		} else {
			if run >= 200 {
				longRuns++
			}
			run = 0
		}
		if c == '\\' && i+3 < n && (content[i+1] == 'x' || content[i+1] == 'X') {
			hexEsc++
		}
		if c == '<' && i+4 < n && content[i+1] == '?' && (content[i+2]|0x20) == 'p' {
			phpTags++
		}
		if !isIdentStart(c) {
			i++
			continue
		}
		j := i + 1
		for j < n && isIdent(content[j]) && j-i < 40 {
			j++
		}
		for k := i + 1; k < j; k++ {
			counts[content[k]]++
			lineLen++
			run++
		}
		tok := string(bytes.ToLower(content[i:j]))
		i = j
		if len(tok) < 2 {
			continue
		}
		if tok[0] == '$' {
			switch tok {
			case "$_get", "$_post", "$_request", "$_cookie", "$_server", "$_files", "$_session", "$globals", "$_env":
			default:
				tok = "$"
			}
		}
		// Skip spaces to see whether this is a call.
		k := i
		for k < n && (content[k] == ' ' || content[k] == '\t') {
			k++
		}
		call := k < n && content[k] == '('
		name := tok
		if call {
			name = "c:" + tok
			if tok == "$" {
				varCalls++
			}
		}
		region := i <= 1500 || i >= n-1500
		if call || region {
			fn(name)
		}
		if prev != "" && region {
			fn(prev + " " + name)
		}
		// Injected code sits at the very top or bottom of an otherwise
		// legitimate file: mark tokens seen there separately.
		if i <= 1500 {
			fn("h:" + name)
		} else if i >= n-1500 {
			fn("t:" + name)
		}
		prev = name
	}
	if lineLen > maxLine {
		maxLine = lineLen
	}
	firstLine := bytes.IndexByte(content, '\n')
	if firstLine < 0 {
		firstLine = n
	}
	fn("s:firstline:" + bucket(firstLine))
	fn("s:size:" + bucket(n))
	fn("s:maxline:" + bucket(maxLine))
	fn("s:hexesc:" + bucket(hexEsc))
	fn("s:longrun:" + bucket(longRuns))
	fn("s:varcall:" + bucket(varCalls))
	fn("s:phptags:" + bucket(phpTags))
	if n > 0 {
		fn("s:nonascii:" + bucket(nonASCII*1000/n))
		fn("s:avgline:" + bucket(n/(lines+1)))
		var h float64
		for _, c := range counts {
			if c > 0 {
				p := float64(c) / float64(n)
				h -= p * math.Log2(p)
			}
		}
		fn("s:entropy:" + strconv.Itoa(int(h*2)))
	}
}
