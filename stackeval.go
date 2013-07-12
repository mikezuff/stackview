package main

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
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

//const targetFunction = "sysAuxClkEnable"
//const targetAddr = 0x308c8b

var (
	dumpLimitLower int64 = -1
	dumpLimitUpper int64 = -1
)

func main() {
	action := "dump"

	args := os.Args

	switch args[1] {
	case "dump": // This is the default
		args = args[1:]
	case "trace":
		action = "trace"
		args = args[1:]
	case "lookup":
		panic("Lookup isn't really supported.")
		action = "lookup"
		args = args[1:]
	case "loadonly":
		action = "loadonly"
		args = args[1:]

	default:
	}

	if len(args) < 3 {
		exit(errors.New("Incorrect args"))
	}

	if len(args) > 3 {
		if len(args) != 5 {
			exit(errors.New("Upper and lower limit required if limits are provided"))
		}

		var err error
		dumpLimitLower, err = strconv.ParseInt(args[3], 0, 64)
		if err != nil {
			exit(fmt.Errorf("Error parsing lower limit: %s", err))
		}
		dumpLimitUpper, err = strconv.ParseInt(args[4], 0, 64)
		if err != nil {
			exit(fmt.Errorf("Error parsing upper limit: %s", err))
		}
	}

	elfBinaryName := args[1]
	dumpFileName := args[2]

	fmt.Printf("Processing binary %s\n", elfBinaryName)
	lf, err := elf.Open(elfBinaryName)
	if err != nil {
		exit(err)
	}
	defer lf.Close()

	printSectionIndex(lf, ".text")
	printSectionIndex(lf, ".data")
	printSectionIndex(lf, ".bss")

	funcs := extractTextSymbols(lf)

	switch action {
	case "dump":
		stackDump := readDump(dumpFileName)
		stackDump.DumpStack(funcs, dumpLimitLower, dumpLimitUpper)
	case "trace":
		stackDump := readDump(dumpFileName)
		stackDump.TraceStack(funcs, dumpLimitLower, dumpLimitUpper)
	case "lookup":
		// Test for some symbol to make sure it works
		s := funcs.Find(targetAddr)
		if s == nil || s.Name != targetFunction {
			panic(fmt.Errorf("Expected %s, got %v at 0x%x",
				targetFunction, s, targetAddr))
		} else {
			fmt.Printf("Found Function %s @0x%x %d bytes\n", s.Name, s.Value, s.Size)
		}
	case "loadonly":
		// Done
	default:
		exit(fmt.Errorf("Uknown action %q", action))
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

func printSectionIndex(f *elf.File, sectionName string) {
	sec := f.Section(sectionName)
	if sec == nil {
		fmt.Printf("No section %s", sectionName)
	} else {
		fmt.Println(sec)
		fmt.Printf("Section %s index %d\n", sectionName, sec.Offset)
	}
}

func extractTextSymbols(lf *elf.File) *FunctionSearch {
	syms, err := lf.Symbols()
	if err != nil {
		panic(err)
	}

	fs := &FunctionSearch{}

	typeCount := make(map[elf.SymType]int)
	loadedTypeCount := make(map[elf.SymType]int)
	secCount := make(map[elf.SectionIndex]int)
	for i, s := range syms {
		if s.Name == targetFunction {
			fmt.Printf("Found Function %s @0x%x %d bytes\n%v\n", s.Name, s.Value, s.Size, s)
		}
		symType := elf.ST_TYPE(s.Info)
		symSec := s.Section - elf.SHN_UNDEF
		typeCount[symType]++

		switch symType {
		case elf.STT_FUNC, elf.STT_OBJECT:
			if strings.HasPrefix(s.Name, "_vx_offset") || s.Name == "cpuPwrIntEnterHook" {
				fmt.Printf("Ignoring symbol #%d %s section %d type %s\n", i, s.Name, symSec, symType)
				continue
			}
			loadedTypeCount[symType]++
			secCount[symSec]++
			fs.Add(&syms[i])
		case elf.STT_FILE, elf.STT_NOTYPE, elf.STT_SECTION:
			// Don't care.
		default:
			fmt.Printf("Ignoring symbol #%d %s section %d type %s\n", i, s.Name, symSec, symType)
		}

	}

	fmt.Println("Saw symType / count seen / count loaded:")
	for k, v := range typeCount {
		fmt.Println(k, v, loadedTypeCount[k])
	}

	fmt.Println("Loaded section / num symbols from section:")
	for k, v := range secCount {
		fmt.Println(k, v)
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
