// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadTcx returns the embedded CollectionSpec for tcx.
func loadTcx() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TcxBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tcx: %w", err)
	}

	return spec, err
}

// loadTcxObjects loads tcx and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tcxObjects
//	*tcxPrograms
//	*tcxMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTcxObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTcx()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tcxSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcxSpecs struct {
	tcxProgramSpecs
	tcxMapSpecs
}

// tcxSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcxProgramSpecs struct {
	EgressProgFunc  *ebpf.ProgramSpec `ebpf:"egress_prog_func"`
	IngressProgFunc *ebpf.ProgramSpec `ebpf:"ingress_prog_func"`
}

// tcxMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcxMapSpecs struct {
	EgressPktCount  *ebpf.MapSpec `ebpf:"egress_pkt_count"`
	IngressPktCount *ebpf.MapSpec `ebpf:"ingress_pkt_count"`
}

// tcxObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTcxObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcxObjects struct {
	tcxPrograms
	tcxMaps
}

func (o *tcxObjects) Close() error {
	return _TcxClose(
		&o.tcxPrograms,
		&o.tcxMaps,
	)
}

// tcxMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTcxObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcxMaps struct {
	EgressPktCount  *ebpf.Map `ebpf:"egress_pkt_count"`
	IngressPktCount *ebpf.Map `ebpf:"ingress_pkt_count"`
}

func (m *tcxMaps) Close() error {
	return _TcxClose(
		m.EgressPktCount,
		m.IngressPktCount,
	)
}

// tcxPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcxObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcxPrograms struct {
	EgressProgFunc  *ebpf.Program `ebpf:"egress_prog_func"`
	IngressProgFunc *ebpf.Program `ebpf:"ingress_prog_func"`
}

func (p *tcxPrograms) Close() error {
	return _TcxClose(
		p.EgressProgFunc,
		p.IngressProgFunc,
	)
}

func _TcxClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tcx_bpfel.o
var _TcxBytes []byte
