package precompiles

/*
#cgo LDFLAGS: -L../target/release -lprecompiles -lm

#include <stdbool.h>
#include <stdint.h>

uint8_t __precompile_expander_verify(const void* data_ptr, const uint32_t data_len, void* ret_val);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func ErrHandle(code byte) error {
	return nil
}

type ExpanderVerifier struct{}

func (e *ExpanderVerifier) RequiredGas(input []byte) uint64 {
	return 7500
}

func (e *ExpanderVerifier) Run(input []byte) ([]byte, error) {
	output := make([]byte, 32)
	cout := unsafe.Pointer(&output[0])

	cstr := unsafe.Pointer(&input[0])
	len := C.uint(len(input))

    fmt.Println("111111111")

	res := C.__precompile_expander_verify(cstr, len, cout)

    fmt.Println("111111111")
    fmt.Println(output)

	return output, ErrHandle(byte(res))
}
