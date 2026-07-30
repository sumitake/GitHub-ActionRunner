// Command portable-ghar-build-identity emits the one validated linker stamp
// used by the immutable release rehearsal.
package main

import (
	"fmt"
	"os"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "portable-ghar-build-identity: invalid arguments")
		os.Exit(2)
	}
	stamp, ok := buildinfo.IdentityStamp(os.Args[1], os.Args[2])
	if !ok {
		fmt.Fprintln(os.Stderr, "portable-ghar-build-identity: invalid identity")
		os.Exit(1)
	}
	fmt.Println(stamp)
}
