// Code generated by https://github.com/gagliardetto/codebox. DO NOT EDIT.

package main

import (
	"io"
	"text/scanner"
)

func TaintStepTest_TextScannerScannerInit_B0I0O0(sourceCQL interface{}) interface{} {
	fromReader656 := sourceCQL.(io.Reader)
	var intoScanner414 scanner.Scanner
	intoScanner414.Init(fromReader656)
	return intoScanner414
}

func TaintStepTest_TextScannerScannerInit_B0I0O1(sourceCQL interface{}) interface{} {
	fromReader518 := sourceCQL.(io.Reader)
	var mediumObjCQL scanner.Scanner
	intoScanner650 := mediumObjCQL.Init(fromReader518)
	return intoScanner650
}

func TaintStepTest_TextScannerScannerTokenText_B0I0O0(sourceCQL interface{}) interface{} {
	fromScanner784 := sourceCQL.(scanner.Scanner)
	intoString957 := fromScanner784.TokenText()
	return intoString957
}

func RunAllTaints_TextScanner() {
	{
		source := newSource(0)
		out := TaintStepTest_TextScannerScannerInit_B0I0O0(source)
		sink(0, out)
	}
	{
		source := newSource(1)
		out := TaintStepTest_TextScannerScannerInit_B0I0O1(source)
		sink(1, out)
	}
	{
		source := newSource(2)
		out := TaintStepTest_TextScannerScannerTokenText_B0I0O0(source)
		sink(2, out)
	}
}
