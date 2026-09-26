package scanner

// stripPHPComments blanks out PHP comments (//, #, /* */) inside PHP code
// blocks, keeping every other byte and all newlines at the same offsets.
// Comments never execute, but documentation such as "set up $_REQUEST
// ( $_GET + $_POST )" looks like code to pattern rules; dropping comments
// removes that source of false positives without hiding anything that runs.
// Strings (including heredoc/nowdoc) are skipped so "//" in a URL is kept,
// and HTML outside <?php ... ?> is left untouched.
func stripPHPComments(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	n := len(src)
	inPHP := false
	blank := func(from, to int) {
		for k := from; k < to && k < n; k++ {
			if out[k] != '\n' && out[k] != '\r' {
				out[k] = ' '
			}
		}
	}
	for i := 0; i < n; {
		c := src[i]
		if !inPHP {
			if c == '<' && i+1 < n && src[i+1] == '?' {
				inPHP = true
				i += 2
				continue
			}
			i++
			continue
		}
		switch {
		case c == '?' && i+1 < n && src[i+1] == '>':
			inPHP = false
			i += 2
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < n && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			i = j + 1
		case c == '<' && i+2 < n && src[i+1] == '<' && src[i+2] == '<':
			// heredoc / nowdoc: <<<ID, <<<"ID" or <<<'ID'
			j := i + 3
			for j < n && (src[j] == ' ' || src[j] == '\t') {
				j++
			}
			if j < n && (src[j] == '\'' || src[j] == '"') {
				j++
			}
			start := j
			for j < n && (src[j] == '_' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			id := src[start:j]
			if len(id) == 0 {
				i += 3
				continue
			}
			// Find a line that starts (after indentation) with the identifier.
			k := j
			for k < n {
				nl := indexByte(src, k, '\n')
				if nl < 0 {
					k = n
					break
				}
				p := nl + 1
				for p < n && (src[p] == ' ' || src[p] == '\t') {
					p++
				}
				if p+len(id) <= n && string(src[p:p+len(id)]) == string(id) {
					k = p + len(id)
					break
				}
				k = p
			}
			i = k
		case c == '#' && !(i+1 < n && src[i+1] == '['), c == '/' && i+1 < n && src[i+1] == '/':
			// Line comment: ends at the newline or at "?>".
			j := i
			for j < n && src[j] != '\n' && !(src[j] == '?' && j+1 < n && src[j+1] == '>') {
				j++
			}
			blank(i, j)
			i = j
		case c == '/' && i+1 < n && src[i+1] == '*':
			j := i + 2
			for j+1 < n && !(src[j] == '*' && src[j+1] == '/') {
				j++
			}
			end := min(n, j+2)
			blank(i, end)
			i = end
		default:
			i++
		}
	}
	return out
}

func indexByte(b []byte, from int, c byte) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
