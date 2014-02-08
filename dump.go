package main

import (
	"debug/elf"
	"fmt"
	"github.com/wsxiaoys/terminal"
	"regexp"
	"strconv"
	"strings"
)

var dumpLineRegexp *regexp.Regexp

func init() {
	dumpLineRegexp = regexp.MustCompile(`^([[:xdigit:]]{16}):((?: [[:xdigit:]]{4}){8})  [|].{8} .{8}[|]`)
}

type Dump struct {
	complete  bool
	start     uint64
	lastStart uint64
	nextAddr  uint64
	buf       []uint64
}

// Expects format:
// 0x01549090:  00000000 00000000 ffffff1f ffffffff   *................*
func (dmp *Dump) Append(line string) error {
	if dmp.complete {
		return fmt.Errorf("Append to already completed dump at 0x%x", dmp.nextAddr)
	}

	if strings.HasPrefix(line, "Physaddr:") || strings.HasPrefix(line, "Phys:") {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			return fmt.Errorf("Corrupt physaddr line")
		}

		// This is the starting address of this section
		addr, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 16, 64)
		if err != nil {
			return fmt.Errorf("Bad physaddr %q", parts[1])
		}

		if dmp.buf == nil {
			dmp.start = addr
			dmp.nextAddr = addr
			dmp.buf = make([]uint64, 0, 2048)
		} else if addr != dmp.nextAddr {
			return fmt.Errorf("Line address 0x%x not expected 0x%x", addr, dmp.nextAddr)
		}

		// offsets are now against this addr
		dmp.lastStart = addr
	} else {
		if !dumpLineRegexp.MatchString(line) {
			//if !dumpLineRegexp.MatchString(line) {
			// Ignore bad format
			fmt.Printf("Ignoring `%s`", line)
			return nil
		}

		f := dumpLineRegexp.FindStringSubmatch(line)
		//fmt.Printf("%d %v", len(f), strings.Join(f, ", "))

		offset, err := strconv.ParseUint(f[1], 16, 64)
		if err != nil {
			return fmt.Errorf("Bad offset %q %q", f[1], f)
		}

		nybs := f[2]

		addr := dmp.lastStart + offset
		if addr != dmp.nextAddr {
			return fmt.Errorf("Line address 0x%x not expected 0x%x", addr, dmp.nextAddr)
		}

		f = strings.Fields(nybs)
		for i := 0; i < len(f); i += 4 {
			addr += uint64(i)
			wordString := strings.Join(f[i:i+4], "")
			v, err := strconv.ParseUint(wordString, 16, 64)
			if err != nil {
				return fmt.Errorf("Invalid int at 0x%x: %s", dmp.nextAddr, err)
			} else {
				dmp.buf = append(dmp.buf, v)
				dmp.nextAddr += 8
			}
		}
	}

	return nil
}

func makeLowerLimit(n uint64) uint64 {
	if n > 0 {
		return n & 3
	}
	return 0
}
func makeUpperLimit(n uint64) uint64 {
	if n < ^uint64(0) {
		return n | 3
	}
	return ^uint64(0)
}

func absDiff(a, b uint64) uint64 {
	if a >= b {
		return a - b
	} else {
		return b - a
	}
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

// PrintLegend prints a legend of the colors used in the dumps
func PrintLegend() {
	terminal.Stdout.Colorf(colorSectionTextZeroLen + ".text zero-length@{|}\n")
	terminal.Stdout.Colorf(colorSectionText + ".text @{|}\n")
	terminal.Stdout.Colorf(colorSectionData + ".data @{|}\n")
	terminal.Stdout.Colorf(colorSectionBss + ".bss @{|}\n")
	terminal.Stdout.Colorf(colorSectionUnknown + "unknown @{|}\n")
	terminal.Stdout.Colorf(colorLocalPointer+"local pointer, within %d@{|}\n", maxStackOffset)
}

// vxworks section offsets were 1=.text 2=.data 3=.bss
// mips is 1=.data 2=.text
func symbolFmtString(symbol *elf.Symbol) string {
	return symbolFmtStringMips(symbol)
}

func symbolFmtStringMips(symbol *elf.Symbol) string {
	switch symbol.Section - elf.SHN_UNDEF {
	case 2: // .text
		if symbol.Size == 0 {
			return colorSectionTextZeroLen
		}
		return colorSectionText
	//case 16: // Both thread local and shared?
	//case 14: // Thread local
	//case 8: // DPS_IN_PRIVATE_MEMORY
	//case 6: // Rmios lib data?
	//case 5: // static const?
	case 1, 5, 6, 8, 14, 16: // .data
		return colorSectionData
	//case 3: // .bss
	//return colorSectionBss
	default:
		return colorSectionUnknown
	}

	panic("unreachable")
}
func symbolFmtStringVxWorks(symbol *elf.Symbol) string {
	switch symbol.Section - elf.SHN_UNDEF {
	case 1: // .text
		if symbol.Size == 0 {
			return colorSectionTextZeroLen
		}
		return colorSectionText
	case 2: // .data
		return colorSectionData
	case 3: // .bss
		return colorSectionBss
	default:
		return colorSectionUnknown
	}

}

func symbolPrint(symbol *elf.Symbol) {
	colorFmt := symbolFmtString(symbol)
	showSectionIndex := false
	if showSectionIndex {
		terminal.Stdout.Colorf(colorFmt+"%16.16s (sec %d) @{|}  ", symbol.Name, symbol.Section-elf.SHN_UNDEF)
	} else {
		terminal.Stdout.Colorf(colorFmt+"%16.16s@{|}  ", symbol.Name)
	}
}

func symbolOffsetString(symbol *elf.Symbol, base uint64) string {
	return fmt.Sprintf("%s{0x%x + 0x%x = 0x%x}", symbol.Name, symbol.Value, base-symbol.Value, base)
}

type word struct {
	V   uint64
	Rel bool
}

// Stack frame is reconstructed backwards from return address to next return address
type stackFrame struct {
	Caller *elf.Symbol
	W      []word
}

func (dmp *Dump) TraceStack(funcs *SymbolTable, lowerLimit, upperLimit uint64) {
	stackStart := -1

	frames := make([]*stackFrame, 0, 10)
	lastFrameOpen := false

	dmp.walk(funcs, lowerLimit, upperLimit,
		func(addr, byteOffset, v uint64, symbol *elf.Symbol) {
			offsetFromCurr := absDiff(v, addr)

			if v == 0xdeadbeef || v == 0xeeeeeeee {
				if stackStart == -1 {
					stackStart = int(addr)
					fmt.Printf("0x%08x:  Blank stack start", addr)
				}
				return
			} else if stackStart != -1 {
				stackStart = -1
				fmt.Printf("       Blank stack ended after %d bytes\n", int(addr)-stackStart)
			}

			fmt.Printf("0x%08x:  ", addr)
			switch {
			case symbol != nil:
				terminal.Stdout.Colorf(symbolFmtString(symbol)+"%s@{|}",
					symbolOffsetString(symbol, v))

				frames = append(frames, &stackFrame{Caller: symbol})
				lastFrameOpen = true
			case offsetFromCurr < maxStackOffset:
				// Pointer into stack
				sign := "+"
				if v < addr {
					sign = "-"
				}
				terminal.Stdout.Colorf(colorLocalPointer+"stk%s%04x@{|}  ", sign, offsetFromCurr)

				if lastFrameOpen {
					frames[len(frames)-1].W = append(frames[len(frames)-1].W,
						word{offsetFromCurr, true})
				}
			default:
				fmt.Printf("%08x  ", v)
				if lastFrameOpen {
					frames[len(frames)-1].W = append(frames[len(frames)-1].W,
						word{v, false})
				}

			}

			fmt.Println()
		})

	if stackStart != -1 {
		fmt.Println("Blank stack never ended??")
	}
}

func (dmp *Dump) DumpStack(funcs *SymbolTable, lowerLimit, upperLimit uint64) {
	details := make([]string, 0, 4)
	dmp.walk(funcs, lowerLimit, upperLimit, func(addr, byteOffset, v uint64, symbol *elf.Symbol) {
		offsetFromCurr := absDiff(v, addr)
		if byteOffset%16 == 0 {
			fmt.Printf("\n0x%016x:  ", addr)
		}

		switch {
		//case v == 0:
		//fmt.Printf("%08x  ", v)
		case symbol != nil:
			symbolPrint(symbol)
			details = append(details, symbolOffsetString(symbol, v))
		case offsetFromCurr < maxStackOffset:
			// Pointer into stack
			sign := "+"
			if v < addr {
				sign = "-"
			}
			terminal.Stdout.Colorf(colorLocalPointer+"stk%s%04x@{|}  ", sign, offsetFromCurr)
		default:
			fmt.Printf("%016x  ", v)
		}

		if byteOffset%16 == 8 && len(details) > 0 {
			fmt.Print(details)
			details = details[:0]
		}

	})
	fmt.Println()
}

type DumpActionFn func(addr, byteOffset, v uint64, symbol *elf.Symbol)

// Interpret the stack dump using the given symbol table.
// Unless limits are -1, limit the dump to the given range.
func (dmp *Dump) walk(funcs *SymbolTable, lowerLimit, upperLimit uint64, actionFn DumpActionFn) {
	ll := makeLowerLimit(lowerLimit)
	ul := makeUpperLimit(upperLimit)

	ignoredSyms := make(map[string]string)
	for i, v := range dmp.buf {
		byteOffset := uint64(i) * 8
		addr := dmp.start + byteOffset

		// Act within limits
		if addr < ll {
			continue
		}
		if addr >= ul {
			fmt.Println()
			return
		}

		symbol := funcs.Find(uint64(v))

		if symbol != nil && !symbolContains(symbol, v) {
			ignoredSyms[symbol.Name] = fmt.Sprintf("Symbol last ignored at 0x%x: %v", v, symbol)
			symbol = nil
		}

		actionFn(addr, byteOffset, v, symbol)
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
