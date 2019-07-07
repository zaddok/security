package security

import (
	"strings"
	"unicode"
)

func ToCamelCase(text string) string {
	words := ToWords(text)
	for i, w := range words {
		if w == "url" {
			words[i] = "URL"
		} else if w == "uuid" {
			words[i] = "UUID"
		} else {
			words[i] = strings.ToUpper(words[i][0:1]) + words[i][1:]
		}
	}
	return strings.Join(words, "")
}

func ToCamelCaseSpaced(text, separator string) string {
	words := ToWords(text)
	for i, w := range words {
		if w == "url" {
			words[i] = "URL"
		} else if w == "uuid" {
			words[i] = "UUID"
		} else {
			words[i] = strings.ToUpper(words[i][0:1]) + words[i][1:]
		}
	}
	return strings.Join(words, separator)
}

func ToWords(text string) []string {
	var words []string
	text = strings.Trim(text, " ")

	word := ""
	var lastChar rune = 0

	for _, v := range text {

		if v >= 'A' && v <= 'Z' {
			if lastChar >= 'A' && lastChar <= 'Z' {
				//	word += string(v)
			}
			if word != "" {
				words = append(words, word)
				word = string(unicode.ToLower(v))
			} else {
				word += string(unicode.ToLower(v))
			}
			lastChar = v
		} else if v >= '0' && v <= '9' {
			if word != "" {
				words = append(words, word)
				word = string(unicode.ToLower(v))
			} else {
				word += string(v)
			}
			lastChar = v
		} else if v == '_' || v == ' ' || v == '-' || v == '.' || v == ',' || v == '[' || v == ']' {
			if word != "" {
				words = append(words, word)
				word = ""
			}
			lastChar = v
		} else {
			if lastChar >= '0' && lastChar <= '9' {
				words = append(words, word)
				word = string(v)
			} else {
				word += string(v)
			}
			lastChar = v
		}
		/*
			if v >= '0' && v <= '9' {
				n += string(v)
			}
			if v >= 'a' && v <= 'z' {
				if capNext {
					n += strings.ToUpper(string(v))
				} else {
					n += string(v)
				}
			}
			if v == '_' || v == ' ' || v == '-' {
				capNext = true
			} else {
				capNext = false
			}*/
	}
	if word != "" {
		words = append(words, word)
	}

	var results []string
	for i := 0; i < len(words); i++ {
		if i+2 < len(words) && words[i] == "u" && words[i+1] == "r" && words[i+2] == "l" {
			results = append(results, "url")
			i = i + 2
		} else if i+3 < len(words) && words[i] == "u" && words[i+1] == "u" && words[i+2] == "i" && words[i+3] == "d" {
			results = append(results, "uuid")
			i = i + 3
		} else {
			results = append(results, words[i])
		}
	}
	return results
}
