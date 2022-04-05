package main

import (
	"fmt"
	"os"
)

func main() {
	app := newApp()
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "runcext: %s\n", err)
		os.Exit(1)
	}
}
