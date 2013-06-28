package main

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

func exit(err error) {
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Usage: stackeval <elfBinary> <stackDump> [lowerLimit] [upperLimit]\n")
	os.Exit(-1)

}

const targetFunction = "intRteOk"
const targetAddr = 0xbfdd1a

var (
	dumpLimitLower int64 = -1
	dumpLimitUpper int64 = -1
)

//const targetFunction = "sysAuxClkEnable"
//const targetAddr = 0x308c8b

func main() {
	if len(os.Args) < 3 {
		exit(errors.New("Incorrect args"))
	}

	if len(os.Args) > 3 {
		if len(os.Args) != 5 {
			exit(errors.New("Upper and lower limit required if limits are provided"))
		}

		var err error
		dumpLimitLower, err = strconv.ParseInt(os.Args[3], 0, 64)
		if err != nil {
			exit(fmt.Errorf("Error parsing lower limit: %s", err))
		}
		dumpLimitUpper, err = strconv.ParseInt(os.Args[4], 0, 64)
		if err != nil {
			exit(fmt.Errorf("Error parsing upper limit: %s", err))
		}
	}

	elfBinaryName := os.Args[1]
	dumpFileName := os.Args[2]

	fmt.Printf("Processing binary %s\n", elfBinaryName)
	lf, err := elf.Open(elfBinaryName)
	if err != nil {
		exit(err)
	}
	defer lf.Close()

	sec := lf.Section(".text")
	if sec == nil {
		fmt.Printf("No section text")
	} else {
		fmt.Println(sec)
		fmt.Println("Section .text index ", sec.Offset)
	}

	funcs := extractTextSymbols(lf)

	if false {
		// Test for some symbol to make sure it works
		s := funcs.Find(targetAddr)
		if s == nil || s.Name != targetFunction {
			panic(fmt.Errorf("Expected %s, got %v at 0x%x",
				targetFunction, s, targetAddr))
		} else {
			fmt.Printf("Found Function %s @0x%x %d bytes\n", s.Name, s.Value, s.Size)
		}
	}

	if false {
		fmt.Printf("Ignoring %s for now.\n", dumpFileName)
	} else {
		stackDump := readDump(dumpFileName)
		stackDump.Walk(funcs, dumpLimitLower, dumpLimitUpper)
	}
}

func readDump(fileName string) *Dump {
	f, err := os.Open(fileName)
	if err != nil {
		exit(err)
	}

	in := bufio.NewReader(f)
	dump := &Dump{}

	lineNum := 0
	for {
		lineNum++
		line, err := in.ReadString('\n')
		appendError := dump.Append(line)
		if appendError != nil {
			exit(fmt.Errorf("Corrupt dump line %d: %s", lineNum, appendError))
		}

		if err != nil {
			if err == io.EOF {
				return dump
			}

			exit(fmt.Errorf("Error reading %s, line %d: ", fileName, lineNum, err))
		}

	}
}

func extractTextSymbols(lf *elf.File) *FunctionSearch {
	syms, err := lf.Symbols()
	if err != nil {
		panic(err)
	}

	fs := &FunctionSearch{}

	for i, s := range syms {
		if s.Name == targetFunction {
			fmt.Printf("Found Function %s @0x%x %d bytes\n%v\n", s.Name, s.Value, s.Size, s)
		}
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			if s.Section != elf.SHN_UNDEF+1 {
				fmt.Printf("Ignoring symbol #%d %s, not in section 1.", i, s.Name)
				continue
			}

			fs.Add(&syms[i])
		} else if (s.Value &^ 0xfff) == 0xbf0000 {
			fmt.Println("Odd symbol: %s\n", s)
		}
	}

	return fs
}

func dumpTable(lf *elf.File) {
	syms, err := lf.Symbols()
	if err != nil {
		panic(err)
	}

	for _, s := range syms {
		fmt.Println(s.Name, s.Value, s.Size, s.Section, s.Info, elf.ST_TYPE(s.Info))
	}
}
