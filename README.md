# ebpf-c-program
ebpf sample

## Getting started

1. Install eBPF Tools and Dependencies
   Install bcc tools and other dependencies:

```shell
sudo apt-get update
sudo apt-get install -y bpfcc-tools clang llvm libelf-dev
sudo apt-get install -y libbpf-dev
ln -sf /usr/include/asm-generic/ /usr/include/asm
```
