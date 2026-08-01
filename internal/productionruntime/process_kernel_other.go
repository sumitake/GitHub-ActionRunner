//go:build !linux

package productionruntime

func NewSystemProcessKernel() (ProcessKernel, error) {
	return nil, ErrProcessAuthorityInvalid
}
