package security

import (
	"testing"
)

func TestStringCamelCase(t *testing.T) {

	for _, v := range [][]string{
		[]string{"AppleFish", "Apple Fish"},
		[]string{"A fish head", "A Fish Head"},
		[]string{"A.fish-head_cat", "A Fish Head Cat"},
		[]string{"AteFishToday...Fun", "Ate Fish Today Fun"},
		[]string{"Address[3].Suburb", "Address 3 Suburb"},
		[]string{"StudentUUID", "Student UUID"},
		[]string{"eat3cat4", "Eat 3 Cat 4"},
		[]string{"myURL", "My URL"},
		[]string{"go2House", "Go 2 House"},
		[]string{"uuid to int", "UUID To Int"},
	} {
		if ToCamelCaseSpaced(v[0], " ") != v[1] {
			t.Fatalf("ToCamelSpaced(\"%s\") failed. Returned: %s", v[0], v[1])
		}
	}

}
