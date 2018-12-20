package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {

	if len(os.Args) != 5 {
		fmt.Println(" bin_to_array package variable.name infile outfile ")
		return
	}

	pkg := os.Args[1]
	varname := os.Args[2]
	infile := os.Args[3]
	outfile := os.Args[4]

	data, err := ioutil.ReadFile(infile)
	if err != nil {
		fmt.Println(err)
		return
	}
	f, err := os.Create(outfile)
	defer f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = f.WriteString("package ")
	_, err = f.WriteString(pkg)
	_, err = f.WriteString("\n\nvar ")
	_, err = f.WriteString(varname)
	_, err = f.WriteString(" []byte = []byte{")
	for i, b := range data {
		_, err = f.WriteString(fmt.Sprintf("%d,", b))
		if i > 0 && i%10 == 0 {
			_, err = f.WriteString("\n")
		}
	}
	_, err = f.WriteString("}")

}
