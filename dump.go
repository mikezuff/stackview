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

func (dmp *Dump) DumpStack(funcs *FunctionSearch, lowerLimit, upperLimit int64) {
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
			colorFmt := "@r"
			if symbol.Size == 0 {
				colorFmt = "@{rY}"
			}

			terminal.Stdout.Colorf(colorFmt+"%8.8s@{|}  ", symbol.Name)
			details = append(details, fmt.Sprintf("%s{0x%x + 0x%x}",
				symbol.Name, symbol.Value, uint64(v)-symbol.Value))
		case offsetFromCurr < maxStackOffset:
			// Pointer into stack
			sign := "+"
			if v < addr {
				sign = "-"
			}
			terminal.Stdout.Colorf("@{.bK}stk%s%04x@{|}  ", sign, offsetFromCurr)
		default:
			fmt.Printf("%08x  ", v)
		}

		if byteOffset % 16 == 0xC && len(details) > 0 {
			fmt.Print(details)
			details = details[:0]
		}

	})
	fmt.Println()
}

type DumpActionFn func(addr, byteOffset, v int64, symbol *elf.Symbol)

// Interpret the stack dump using the given symbol table.
// Unless limits are -1, limit the dump to the given range.
func (dmp *Dump) walk(funcs *FunctionSearch, lowerLimit, upperLimit int64, actionFn DumpActionFn) {
	ll := makeLowerLimit(lowerLimit)
	ul := makeUpperLimit(upperLimit)

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

		actionFn(addr, byteOffset, v, symbol)
	}
}

const maxStackOffset = 0x1000
