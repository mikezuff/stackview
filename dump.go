package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"github.com/wsxiaoys/terminal"
	"math"
	"strconv"
	"strings"
)

type Dump struct {
	complete bool
	start    int64
	nextAddr int64
	buf      []uint32
}

// Expects format:
// 0x01549090:  00000000 00000000 ffffff1f ffffffff   *................*
func (dmp *Dump) Append(line string) error {
	if dmp.complete {
		return fmt.Errorf("Append to already completed dump at 0x%x", dmp.nextAddr)
	}

	if !strings.HasPrefix(line, "0x") || []byte(line)[10] != ':' {
		// Ignore bad format
		//fmt.Println("Ignoring %20s", line)
		return nil
	}

	var addr int64
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	if !strings.HasPrefix(fields[0], "0x") || !strings.HasSuffix(fields[0], ":") {
		return fmt.Errorf("Invalid addr. Read %v", fields)
	}

	addr, err := strconv.ParseInt(
		strings.TrimLeft(strings.TrimRight(fields[0], ":"), "0x"), 16, 64)
	if err != nil {
		return fmt.Errorf("Invalid addr: %s", err)
	}

	if dmp.buf == nil {
		dmp.start = addr
		dmp.nextAddr = addr
		dmp.buf = make([]uint32, 0, 2048)
	} else if addr != dmp.nextAddr {
		return fmt.Errorf("Line address 0x%x not expected 0x%x", addr, dmp.nextAddr)
	}

	i := 1
	for ; i <= 4; i++ {
		a, err := strconv.ParseInt(fields[i], 16, 64)
		if err != nil {
			return fmt.Errorf("Invalid int at 0x%x: %s", dmp.nextAddr, err)
		} else {
			dmp.nextAddr += 4
			dmp.buf = append(dmp.buf, uint32(a))
		}
	}
	if i < 4 {
		dmp.complete = true
	}

	//fmt.Printf("Read from dump %d at 0x%08x\n", i, addr)
	e := len(dmp.buf)
	reconstructed := []byte(fmt.Sprintf("0x%08x:  %08x %08x %08x %08x", addr,
		dmp.buf[e-4], dmp.buf[e-3], dmp.buf[e-2], dmp.buf[e-1]))
	orig := []byte(line)[:len(reconstructed)]
	if bytes.Compare(reconstructed, orig) != 0 {
		fmt.Printf("Didn't read right:\nOrig:\n%q\nReconstructed:\n%q\n",
			orig, reconstructed)
	}

	return nil
}

func makeLowerLimit(n int64) int64 {
	if n > 0 {
		return n - (n % 16)
	}
	return math.MinInt64
}
func makeUpperLimit(n int64) int64 {
	if n > 0 {
		return n + (16 - (n % 16))
	}
	return math.MaxInt64
}

func absDiff(a, b int64) int64 {
	if a >= b {
		return a - b
	} else {
		return b - a
	}
}

const (
	maxEmptySymbolLength    = 0x10000
	maxStackOffset          = 0x1000

	colorSectionTextZeroLen = "@{rY}"
	colorSectionText        = "@{kY}"
	colorSectionData        = "@{kG}"
	colorSectionBss         = "@{wG}"
	colorSectionUnknown     = ""
	colorLocalPointer       = "@{.bK}"
)

// PrintLegend prints a legend of the colors used in the dumps
func PrintLegend() {
	terminal.Stdout.Colorf(colorSectionTextZeroLen + ".text zero-length@{|}\n")
	terminal.Stdout.Colorf(colorSectionText + ".text @{|}\n")
	terminal.Stdout.Colorf(colorSectionData + ".data @{|}\n")
	terminal.Stdout.Colorf(colorSectionBss + ".bss @{|}\n")
	terminal.Stdout.Colorf(colorLocalPointer+"local pointer, within %d@{|}\n", maxStackOffset)
}

func symbolFmtString(symbol *elf.Symbol) string {
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
	terminal.Stdout.Colorf(colorFmt+"%8.8s@{|}  ", symbol.Name)
}

func symbolOffsetString(symbol *elf.Symbol, base int64) string {
	return fmt.Sprintf("%s{0x%x + 0x%x}", symbol.Name, symbol.Value, uint64(base)-symbol.Value)
}

type word struct {
	V   int64
	Rel bool
}

// Stack frame is reconstructed backwards from return address to next return address
type stackFrame struct {
	Caller *elf.Symbol
	W      []word
}

func (dmp *Dump) TraceStack(funcs *SymbolTable, lowerLimit, upperLimit int64) {
	stackStart := -1

	frames := make([]*stackFrame, 0, 10)
	lastFrameOpen := false

	dmp.walk(funcs, lowerLimit, upperLimit,
		func(addr, byteOffset, v int64, symbol *elf.Symbol) {
			offsetFromCurr := absDiff(v, addr)

			if v == 0xeeeeeeee {
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

func (dmp *Dump) DumpStack(funcs *SymbolTable, lowerLimit, upperLimit int64) {
	details := make([]string, 0, 4)
	dmp.walk(funcs, lowerLimit, upperLimit, func(addr, byteOffset, v int64, symbol *elf.Symbol) {
		offsetFromCurr := absDiff(v, addr)
		if byteOffset%16 == 0 {
			fmt.Printf("\n0x%08x:  ", addr)
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
			fmt.Printf("%08x  ", v)
		}

		if byteOffset%16 == 0xC && len(details) > 0 {
			fmt.Print(details)
			details = details[:0]
		}

	})
	fmt.Println()
}

type DumpActionFn func(addr, byteOffset, v int64, symbol *elf.Symbol)

// Interpret the stack dump using the given symbol table.
// Unless limits are -1, limit the dump to the given range.
func (dmp *Dump) walk(funcs *SymbolTable, lowerLimit, upperLimit int64, actionFn DumpActionFn) {
	ll := makeLowerLimit(lowerLimit)
	ul := makeUpperLimit(upperLimit)

	ignoredSyms := make(map[string]string)
	for i, v32 := range dmp.buf {
		v := int64(v32)

		byteOffset := int64(i) * 4
		addr := dmp.start + int64(byteOffset)

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

func symbolContains(symbol *elf.Symbol, addr int64) bool {
	ua := uint64(addr)
	size := symbol.Size
	if size == 0 {
		size = maxEmptySymbolLength
	}

	return ua-symbol.Value < size
}
