package main

import (
	"bytes"
	"fmt"
	"github.com/wsxiaoys/terminal"
	"strconv"
	"strings"
)

type Dump struct {
	start    int64
	nextAddr int64
	buf      []uint32
}

// Expects format:
// 0x01549090:  00000000 00000000 ffffff1f ffffffff   *................*
func (dmp *Dump) Append(line string) error {
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

func (dmp *Dump) Walk(funcs *FunctionSearch) {
	syms := make([]string, 0, 4)

	funcs.Top()

	for i, v32 := range dmp.buf {
		v := int64(v32)

		byteOffset := i * 4
		addr := dmp.start + int64(byteOffset)

		if byteOffset%16 == 0 {
			fmt.Printf("\n0x%08x:  ", addr)
		}

		var delta int64
		if v >= addr {
			delta = v - addr
		} else {
			delta = addr - v
		}

		symbol := funcs.Find(uint64(v))

		const thresh = 0x1000
		switch {
		//case v == 0:
		//fmt.Printf("%08x  ", v)
		case symbol != nil:
			colorFmt := "@r"
			if symbol.Size == 0 {
				colorFmt = "@{rY}"
			}

			terminal.Stdout.Colorf(colorFmt+"%8.8s@{|}  ", symbol.Name)
			syms = append(syms, fmt.Sprintf("%s{0x%x}", symbol.Name, symbol.Value))
		case delta < thresh:
			// Pointer into stack
			terminal.Stdout.Colorf("@{.bK}stk%05x@{|}  ", delta)
		default:
			fmt.Printf("%08x  ", v)
		}

		if i%4 == 3 && len(syms) > 0 {
			fmt.Print(syms)
			syms = syms[:0]
		}

	}

	fmt.Println()
}
