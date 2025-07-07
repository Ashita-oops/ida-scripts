package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"

	"github.com/asty-org/asty/asty"
)

// func memequal(a, b unsafe.Pointer, size uintptr) bool

type StatusCode int

const (
	OK = iota
	Error
	NeedMore
)

type Input struct {
	GoSource string `json:"go_source"`
}

type Output struct {
	Error  string         `json:"error,omitempty"`
	Status StatusCode     `json:"status"`
	Result *asty.FileNode `json:"result"`
}

// func extractName(src string, n ast.Node) string {
// 	if !(n.Pos().IsValid() && n.End().IsValid()) {
// 		return ""
// 	}
// 	return src[n.Pos()-1 : n.End()-1]
// }

func printErrJSON(err error) {
	output := Output{
		Error:  err.Error(),
		Status: Error,
	}

	serialized, err := json.Marshal(output)
	if err != nil {
		panic("panic! at the disco no way serialize not okay baby")
	}

	fmt.Println(string(serialized))
}

func getAndParseInput() (*Input, error) {
	reader := bufio.NewReader(os.Stdin)
	inputstr, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("input JSON object: %s", err.Error())
	}

	input := &Input{}
	if err := json.Unmarshal([]byte(inputstr), input); err != nil {
		return nil, fmt.Errorf("unmarshal JSON object: %s", err.Error())
	}

	if len(input.GoSource) == 0 {
		return nil, fmt.Errorf("no input Go source code found")
	}

	return input, nil
}

func getASTFile(input *Input) (*ast.File, error) {
	// Create a FileSet for position information
	fset := token.NewFileSet()

	// Parse the source code
	file, err := parser.ParseFile(fset, "", input.GoSource, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing file: %s", err.Error())
	}

	return file, nil
}

func printASTJSON(file *ast.File) {
	marshaller := asty.NewMarshaller(asty.Options{
		WithPositions: true,
	})

	node := marshaller.MarshalFile(file)
	output := Output{
		Status: OK,
		Result: node,
	}

	serialized, err := json.Marshal(output)
	if err != nil {
		panic("panic! at the disco no way serialize not okay baby")
	}

	fmt.Println(string(serialized))
}

func main() {
	input, err := getAndParseInput()
	if err != nil {
		printErrJSON(err)
		return
	}

	file, err := getASTFile(input)
	if err != nil {
		printErrJSON(err)
		return
	}

	printASTJSON(file)
}
