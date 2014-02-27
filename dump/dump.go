package dump

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"github.com/wsxiaoys/terminal"
	"io"
	"strconv"
)

type DumpS struct {
	address   uint64
	buf       []byte
	archSize  int
	byteOrder binary.ByteOrder
}

// TranslateStack prints the dump using symbols from syms.
func (dmp *DumpS) TranslateStack(syms *SymbolTable, lowerLimit, upperLimit uint64, sections []*elf.Section) {
	ignoredSyms := make(map[string]string)
	details := make([]string, 0, 4)

	var incr uint64
	var addrWidth int
	switch dmp.archSize {
	case 64:
		incr = 8
		addrWidth = 16
	case 32:
		incr = 4
		addrWidth = 8
	default:
		panic("Unhandled archSize")
	}

	i := uint64(0)
	// Just dump unaligned bytes at start
	if dmp.address%incr > 0 {
		i = incr - (dmp.address % incr)
		if i > 0 {
			fmt.Printf("\n0x%0*x:  ", addrWidth, dmp.address)
			for j := uint64(0); j < i; j++ {
				fmt.Printf("%02x ", dmp.buf[j])
			}
		}
	}

	fmtAlign := 0
	symsWide := 2
	for i < uint64(len(dmp.buf)) {
		addr := dmp.address + i

		// Act within limits
		if addr < lowerLimit {
			continue
		}
		if addr >= upperLimit {
			fmt.Println()
			return
		}

		if fmtAlign%symsWide == 0 {
			fmt.Printf("\n0x%0*x:  ", addrWidth, addr)
		}

		// Just dump unaligned bytes at the end
		if rem := uint64(len(dmp.buf)) - i; rem < incr {
			for _, b := range dmp.buf[i:] {
				fmt.Printf("%02x ", b)
			}
			fmt.Println()
			return
		}

		var word uint64

		switch dmp.archSize {
		case 64:
			word = dmp.byteOrder.Uint64(dmp.buf[i : i+8])
		case 32:
			word = uint64(dmp.byteOrder.Uint32(dmp.buf[i : i+4]))
		default:
			panic("Unhandled archSize")
		}

		symbol := syms.Find(word)
		if symbol != nil && !symbolContains(symbol, word) {
			ignoredSyms[symbol.Name] = fmt.Sprintf("Symbol last ignored at 0x%x: %v", word, symbol)
			symbol = nil
		}

		offsetFromCurr := absDiff(word, addr)

		switch {
		case symbol != nil:
			symbolPrint(symbol, addrWidth, sections)
			details = append(details, symbolOffsetString(symbol, word))
		case offsetFromCurr < maxStackOffset:
			// Pointer into stack
			sign := "+"
			if word < addr {
				sign = "-"
			}
			terminal.Stdout.Colorf(colorLocalPointer+"stk%s%0*xh@{|}  ", sign, addrWidth-5, offsetFromCurr)
		default:
			fmt.Printf("%0*x  ", addrWidth, word)
		}

		if fmtAlign%symsWide == (symsWide-1) && len(details) > 0 {
			fmt.Print(details)
			details = details[:0]
		}

		i += incr
		fmtAlign++
	}

	fmt.Println()
	for _, s := range ignoredSyms {
		fmt.Println(s)
	}
}

func symbolContains(symbol *elf.Symbol, addr uint64) bool {
	size := symbol.Size
	if size == 0 {
		size = maxEmptySymbolLength
	}

	return addr-symbol.Value < size
}

type DumpParser interface {
	IsAbsOffsetLine(line []byte) (bool, uint64)
	IsDataLine(line []byte) (bool, uint64, []byte)
}

// ReadDumpFrom loads a DumpS from a text stack memory dump.
func ReadDumpFrom(r io.Reader, byteOrder binary.ByteOrder, archSize int, parser DumpParser) (*DumpS, error) {
	in := bufio.NewReader(r)

	var absAddr bool
	var startAddr uint64
	var nextAddr uint64
	var Buf []byte

	lineNum := 0
	for {
		lineNum++
		line, readErr := in.ReadBytes('\n')
		if match, offset := parser.IsAbsOffsetLine(line); match {
			if startAddr == 0 {
				startAddr = offset
				nextAddr = offset
				absAddr = true
			} else if nextAddr != offset {
				return nil, fmt.Errorf("Expected absolute address 0x%x on line %d", nextAddr, lineNum)
			}
		} else if match, offset, btext := parser.IsDataLine(line); match {
			if startAddr == 0 && !absAddr {
				startAddr = offset // Haven't seen an abs offset yet, assume this line offset is abs
				nextAddr = offset
			} else if !absAddr && nextAddr != offset {
				return nil, fmt.Errorf("Expected address 0x%x, got 0x%x on line %d",
					nextAddr, offset, lineNum)
			} else if absAddr && nextAddr != startAddr+offset {
				return nil, fmt.Errorf("Expected address 0x%x, got 0x%x + 0x%x on line %d",
					nextAddr, startAddr, offset, lineNum)
			}

            // XXX: this doesn't handle leading misalignment correctly
            // The missing bytes make nextAddr be less than the offset of the next line
			lineBytes, err := convertDumpBytes(btext, byteOrder)
			if err != nil {
				return nil, fmt.Errorf("Dump format error line %d: %s", lineNum, err)
			}

			Buf = append(Buf, lineBytes...)
			nextAddr += uint64(len(lineBytes))
		}

		if readErr != nil {
			if readErr == io.EOF {
				return &DumpS{startAddr, Buf, archSize, byteOrder}, nil
			}

			return nil, fmt.Errorf("Error reading dumpfile, line %d: %v", lineNum, readErr)
		}
	}
	panic("Unreachable")
}

func convertDumpBytes(btext []byte, byteOrder binary.ByteOrder) ([]byte, error) {
	trimmed := bytes.TrimSpace(btext)
	words := bytes.Split(trimmed, []byte(" "))
	sz := len(words[0])

	var linebytes []byte
	scr := make([]byte, 8)
	for i, word := range words {
		if len(word) != sz && i != len(words)-1 {
			return nil, fmt.Errorf("Inconsistent word size")
		}

		b, err := strconv.ParseUint(string(word), 16, 64)
		if err != nil {
			return nil, err
		}

		switch {
		case len(word) <= 2:
			linebytes = append(linebytes, byte(b))
		case len(word) <= 4:
			byteOrder.PutUint16(scr[0:2], uint16(b))
			linebytes = append(linebytes, scr[0:2]...)
		case len(word) <= 8:
			byteOrder.PutUint32(scr[0:4], uint32(b))
			linebytes = append(linebytes, scr[0:4]...)
		case len(word) <= 16:
			byteOrder.PutUint64(scr[0:8], b)
			linebytes = append(linebytes, scr[0:8]...)
		default:
			return nil, fmt.Errorf("Oversize word")
		}
	}

	return linebytes, nil
}

func absDiff(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return b - a
}

const (
	maxEmptySymbolLength = 0x10000
	maxStackOffset       = 0x1000

	colorSectionTextZeroLen = "@{rY}"
	colorSectionText        = "@{kY}"
	colorSectionData        = "@{kG}"
	colorSectionBss         = "@{wG}"
	colorSectionUnknown     = "@{cB}"
	colorLocalPointer       = "@{.bK}"
)

// PrintLegend prints a legend of the colors used in the dumps.
func PrintLegend() {
	fmt.Println("Legend:")
	terminal.Stdout.Colorf("\t" + colorSectionTextZeroLen + ".text zero-length@{|}\n")
	terminal.Stdout.Colorf("\t" + colorSectionText + ".text @{|}\n")
	terminal.Stdout.Colorf("\t" + colorSectionData + ".data @{|}\n")
	terminal.Stdout.Colorf("\t" + colorSectionBss + ".bss @{|}\n")
	terminal.Stdout.Colorf("\t" + colorSectionUnknown + "unknown @{|}\n")
	terminal.Stdout.Colorf("\t"+colorLocalPointer+"local pointer, within %d@{|}\n", maxStackOffset)
}

func symbolFmtString(symbol *elf.Symbol, sections []*elf.Section) string {
	secIndex := int(symbol.Section)
	if secIndex >= len(sections) {
		return colorSectionUnknown
	}

	switch {
	case sections[secIndex].Flags&elf.SHF_EXECINSTR != 0:
		if symbol.Size == 0 {
			return colorSectionTextZeroLen
		}
		return colorSectionText
	case sections[secIndex].Flags&elf.SHF_WRITE != 0 &&
		sections[secIndex].Flags&elf.SHF_ALLOC != 0:
		return colorSectionBss
	case sections[secIndex].Flags&elf.SHF_ALLOC != 0:
		return colorSectionData
	default:
		return colorSectionUnknown
	}
	panic("Unreachable")
}

func symbolPrint(symbol *elf.Symbol, addrWidth int, sections []*elf.Section) {
	colorFmt := symbolFmtString(symbol, sections)
	showSectionIndex := false
	if showSectionIndex {
		terminal.Stdout.Colorf(colorFmt+"%*.*s (sec %d) @{|}  ", addrWidth, addrWidth, symbol.Name, symbol.Section-elf.SHN_UNDEF)
	} else {
		terminal.Stdout.Colorf(colorFmt+"%*.*s@{|}  ", addrWidth, addrWidth, symbol.Name)
	}
}

func symbolOffsetString(symbol *elf.Symbol, base uint64) string {
	return fmt.Sprintf("%s{0x%x + 0x%x = 0x%x}", symbol.Name, symbol.Value, base-symbol.Value, base)
}
