// stackview interprets a memory dump using symbols from a given ELF binary.
// It prints using ANSI color codes. Piping into 'less -R' can be useful for review.
// See Hacking section in README.md if you have problems.
package main

import (
	"debug/elf"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/mikezuff/stackview/dump"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// IgnoreSymbol returns true if the symbol should be ignored if its address is found in a dump.
// This is useful for symbols that are at common addresses like 0 and 0xeeeeeeee.
func IgnoreSymbol(s elf.Symbol) bool {
	return strings.HasSuffix(s.Name, "_hook") || // RMIOS
		strings.HasPrefix(s.Name, "_vx_offset") || s.Name == "cpuPwrIntEnterHook" // vxworks
}

// DataLineRE should match a dump line that contains an absolute offset for the dump. Dumps are expected to be contiguous. The first submatch is the offset.
var DataLineRE = regexp.MustCompile(`^(?:0x)?([[:xdigit:]]+): *((?: *[[:xdigit:]])+) *[|*].{8} ?.{8}[|*]`)

// OffsetLineRE should match dump lines containing memory values. The first submatch should be the offset of the first byte in the line. The second submatch should be the memory value text in word sizes of 1 to 8 bytes.
var OffsetLineRE = regexp.MustCompile(`^(?:Physaddr:|Phys:)(?:0x)?([[:xdigit:]]+)`)

type GeneralDumpParser struct{}

func (g GeneralDumpParser) IsAbsOffsetLine(line []byte) (bool, uint64) {
	submatch := OffsetLineRE.FindSubmatch(line)
	if submatch == nil {
		return false, 0
	}

	offset, err := strconv.ParseUint(string(submatch[1]), 16, 64)
	if err != nil {
		panic(fmt.Sprintf("Regex OffsetLineRE matched line %q but offset parse failed %s",
			string(line), err))
	}

	return true, offset
}

func (g GeneralDumpParser) IsDataLine(line []byte) (bool, uint64, []byte) {
	submatch := DataLineRE.FindSubmatch(line)
	if submatch == nil {
		return false, 0, nil
	}

	offset, err := strconv.ParseUint(string(submatch[1]), 16, 64)
	if err != nil {
		panic(fmt.Sprintf("Regex DataLineRE matched line %q but offset parse failed %s",
			string(line), err))
	}

	return true, offset, submatch[2]
}

var flagVerbose = flag.Bool("verbose", false, "")
var flagDumpSectionsOnly = flag.Bool("show-sections", false, "Print the elf sections, then quit.")

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
	}

	printUsage()
	os.Exit(-1)
}

func printUsage() {
	fmt.Println("Usage: stackview <elfBinary> <stackDump>")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Example: 'stackview vxWorks.st stack.dump'")
}

func main() {
	flag.Usage = printUsage
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		errExit(fmt.Errorf("Not enough arguments."))
	}
	elfBinaryName := args[0]

	elfFile, err := elf.Open(elfBinaryName)
	if err != nil {
		errExit(err)
	}
	defer elfFile.Close()

	if *flagDumpSectionsOnly {
		printSections(elfFile)
		os.Exit(0)
	}

	if len(args) != 2 {
		errExit(fmt.Errorf("Not enough arguments."))
	}
	dumpFileName := args[1]

	syms := extractSymbols(elfFile)

	var archSize int
	switch elfFile.FileHeader.Class {
	case elf.ELFCLASS64:
		archSize = 64
	case elf.ELFCLASSNONE:
		fmt.Println("ELF class doesn't specify architecture size. Assuming 32-bit.")
		fallthrough
	case elf.ELFCLASS32: // ok
		archSize = 32
	default:
		errExit(fmt.Errorf("Unhandled ELF EI_CLASS %d", elfFile.FileHeader.Class))
	}

	var byteOrder binary.ByteOrder
	switch elfFile.FileHeader.Data {
	case elf.ELFDATA2LSB:
		byteOrder = binary.LittleEndian
	case elf.ELFDATA2MSB:
		byteOrder = binary.BigEndian
	default:
		errExit(fmt.Errorf("ELF byte order unspecified"))
	}

	fmt.Printf("Dumping symbols from %s %d-bit %s\n", elfBinaryName, archSize, byteOrder)

	f, err := os.Open(dumpFileName)
	if err != nil {
		errExit(err)
	}
	defer f.Close()

	var g GeneralDumpParser
	stackDump, err := dump.ReadDumpFrom(f, byteOrder, archSize, &g)
	if err != nil {
		errExit(fmt.Errorf("Error loading stack dump %s: %s", dumpFileName, err))
	}

	stackDump.TranslateStack(syms, 0, ^uint64(0), elfFile.Sections)
	dump.PrintLegend()
}

func printSections(elfFile *elf.File) {
	for i, sec := range elfFile.Sections {
		fmt.Println(i, sec.Name, sec.Type, sec.Flags)
	}
}

func extractSymbols(elfFile *elf.File) *dump.SymbolTable {
	syms, err := elfFile.Symbols()
	if err != nil {
		panic(err)
	}

	fs := &dump.SymbolTable{}

	loadedTypeCount := make(map[elf.SymType]int)
	secCount := make(map[elf.SectionIndex]int)
	for i, s := range syms {
		symType := elf.ST_TYPE(s.Info)
		symSec := s.Section - elf.SHN_UNDEF

		switch symType {
		case elf.STT_FUNC, elf.STT_OBJECT:
			if IgnoreSymbol(s) {
				if *flagVerbose {
					fmt.Printf("Ignoring symbol #%d %s section %d type %s at %x\n",
						i, s.Name, symSec, symType, s.Value)
				}
				continue
			}

			loadedTypeCount[symType]++
			secCount[symSec]++
			fs.Add(&syms[i])
		case elf.STT_FILE, elf.STT_SECTION, elf.STT_NOTYPE:
			// ignore these quietly
		default:
			fmt.Printf("Ignoring symbol #%d %s section %d type %s\n", i, s.Name, symSec, symType)
		}

	}

	return fs
}
