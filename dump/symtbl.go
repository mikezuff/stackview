package dump

import (
	"bytes"
	"debug/elf"
	"fmt"
	"sort"
)

type Symbols []*elf.Symbol

func (s Symbols) Len() int      { return len(s) }
func (s Symbols) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type ByAddr struct{ Symbols }

func (s ByAddr) Less(i, j int) bool { return s.Symbols[i].Value < s.Symbols[j].Value }

type SymbolTable struct {
	sorted bool
	syms   Symbols
}

func (fs *SymbolTable) PrintTop() {
	if fs.sorted == false {
		sort.Sort(ByAddr{fs.syms})
		fs.sorted = true
	}
	for i := 0; i < 5; i++ {
		fmt.Println(fs.syms[i])
	}
}

func (fs *SymbolTable) String() string {
	buf := &bytes.Buffer{}
	for _, s := range fs.syms {
		fmt.Fprintln(buf, s)
	}

	return buf.String()
}
func (fs *SymbolTable) Add(sym *elf.Symbol) {
	fs.sorted = false
	fs.syms = append(fs.syms, sym)
}

func (fs *SymbolTable) Find(addr uint64) *elf.Symbol {
	if fs.sorted == false {
		sort.Sort(ByAddr{fs.syms})
		fs.sorted = true
	}

	// Search for the smallest address larger than the search address
	i := sort.Search(len(fs.syms), func(n int) bool {
		return fs.syms[n].Value > addr
	})

	// Then find if the previous address contains the requested address
	if i > 0 {
		s := fs.syms[i-1]
		if s.Value <= addr && (s.Value+s.Size > addr || s.Size == 0) {
			return s
		}
	}

	return nil
}
