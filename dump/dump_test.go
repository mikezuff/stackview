package dump

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var absOffsetTests = []struct {
	line   string
	offset uint64
}{
	{"Physaddr:10867C000", 0x10867c000},
	{"Physaddr:0x20487C000", 0x20487c000},
}

func TestIsAbsOffset(t *testing.T) {
	for _, td := range absOffsetTests {
		valid, offset := IsAbsOffsetLine([]byte(td.line))
		if !valid {
			t.Fatalf("Expected valid: %s", td.line)
		}
		if offset != td.offset {
			t.Fatalf("Expected offset 0x%x, got 0x%x", td.offset, offset)
		}
	}
}

var dataLineTests = []struct {
	line      string
	offset    uint64
	b         []byte
	byteOrder binary.ByteOrder
}{
	{`0000000000000080: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  |........ ........|`,
		0x80, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		binary.BigEndian},
	{`0000000000000080: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  |........ ........|`,
		0x80, []byte{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 0xb, 0xa, 0xd, 0xc, 0xf, 0xe},
		binary.LittleEndian},
	{`0x01549090:  01020304 05060708 a1a2a3a4 a5a6a7a8   *................*`,
		0x1549090,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		binary.BigEndian},
	{`0x9098:  01020304 05060708 a1a2a3a4 a5a6a7a8   *................*`,
		0x9098,
		[]byte{4, 3, 2, 1, 8, 7, 6, 5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa8, 0xa7, 0xa6, 0xa5},
		binary.LittleEndian},
	{`0x01549090:  41 02 03 04 05 06 07 08 a1 a2 a3 a4 a5 a6 a7 a8   *................*`,
		0x1549090,
		[]byte{0x41, 2, 3, 4, 5, 6, 7, 8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		binary.LittleEndian},
	{`0x01549090:  0102030405060708 a1a2a3a4a5a6a7a8   *................*`,
		0x1549090,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		binary.BigEndian},
	{`0x9098:  0102030405060708 a1a2a3a4a5a6a7a8   *................*`,
		0x9098,
		[]byte{8, 7, 6, 5, 4, 3, 2, 1, 0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1},
		binary.LittleEndian},
	{`0x01549090:  01020304 05060708 a1a2a3a4 a5         *.............   *`,
		0x1549090,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5},
		binary.BigEndian},
}

func TestByteConv(t *testing.T) {
	for _, td := range dataLineTests {
		isData, offset, bstr := IsDataLine([]byte(td.line))
		if !isData {
			t.Fatalf("Expected dataline %s", td.line)
		}
		if offset != td.offset {
			t.Fatalf("Offset = 0x%x, want 0x%x", offset, td.offset)
		}
		b, err := ConvertDumpBytes(bstr, td.byteOrder)
		if err != nil {
			t.Fatalf("Err converting %q from %q: %s", bstr, td.line, err)
		}
		if bytes.Compare(b, td.b) != 0 {
			t.Fatalf("Bytes = %v, want %v", b, td.b)
		}
	}
}
