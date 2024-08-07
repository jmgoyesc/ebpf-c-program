package main

import (
	"C"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type HttpRequest struct {
	Path            [1024]byte
	Method          [8]byte
	Headers         [1024]byte
	RequestPayload  [1024]byte
	ResponsePayload [1024]byte
}

func main() {
	// Load the compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("ebpf_http.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	objs := struct {
		KprobeTcpSendmsg *ebpf.Program `ebpf:"kprobe__tcp_sendmsg"`
		Events           *ebpf.Map     `ebpf:"events"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}

	kprobe, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kprobe.Close()

	// Set up the perf event reader
	reader, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %v", err)
	}
	defer reader.Close()

	// Handle system signals for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Listening for HTTP requests...")

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Fatalf("Failed to read from perf event reader: %v", err)
			}

			var req HttpRequest
			if err := record.Unmarshal(&req); err != nil {
				log.Fatalf("Failed to unmarshal perf event: %v", err)
			}

			fmt.Printf("Path: %s\n", string(req.Path[:]))
			fmt.Printf("Method: %s\n", string(req.Method[:]))
			fmt.Printf("Headers: %s\n", string(req.Headers[:]))
			fmt.Printf("Request Payload: %s\n", string(req.RequestPayload[:]))
			fmt.Printf("Response Payload: %s\n", string(req.ResponsePayload[:]))
		}
	}()

	<-sigs
	fmt.Println("Exiting...")
}
