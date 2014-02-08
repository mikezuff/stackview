stackview
=========

Simple tool that helps visualize symbols within a memory dump.

Build
=====
`cd stackview`
`go build -o stackview *.go`

Usage
=====

 `stackview [command] <elfBinary> <stackDump> [lowerLimit] [upperLimit]`

 `stackview dump vxWorks.st stack.dump`
 `stackview trace vxWorks.st stack.dump 0x94be750 0x94be9f0`

![alt text](https://raw.github.com/mikezuff/stackview/master/screenshot.png "Screenshot")


