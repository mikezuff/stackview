stackview
=========

Simple tool that helps visualize symbols within a hex dump of the stack. It is
designed for embedded software crashes where a dump of thread stack memory is available, 
but no stack trace is available.


Build
=====

[Install Go](http://golang.org/doc/install). Go 1.1 is required.


    go get github.com/mikezuff/stackview
    cd $GOPATH/src/github.com/mikezuff/stackview
    go build stackview.go

Usage
=====

 `stackview <elfBinary> <stackDump>`

 `stackview vxWorks.st stack.dump`

To turn the file stack.dump from this:

    0x094bd740:  00d07ca8 0161d6d4 099d0168 00000072   *.|....a.h...r...*
    0x094bd750:  0161d520 000000cd 099d0128 094bd770   * .a.....(...p.K.*
    0x094bd760:  00d063f4 0161d6d4 00000000 099d0168   *.c....a.....h...*
    0x094bd770:  094bd790 00d07ca8 0161d6d4 0161d520   *..K..|....a. .a.*
    0x094bd780:  000000cd 099d0128 094bd79c 00d063f4   *....(.....K..c..*
    0x094bd790:  0161d6d4 00000000 099d0168 0161d520   *..a.....h... .a.*
    ...

Into this:
![alt text](https://raw.github.com/mikezuff/stackview/master/screenshot.png "Screenshot")

Hacking
=======

Stackview is written to handle vxworks and rmios kernel executables. You may need 
to adjust it for your system. 

Stackview uses regular expressions to parse the source address and dump bytes from a hexdump.
If you are getting format errors when stackview is loading your dump, you may need to
edit DataLineRE or OffsetLineRE or replace GeneralDumpParser with something specific
to your needs.

If func IgnoreSymbol returns true, the symbol name won't be printed in the output.
