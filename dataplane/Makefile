TARGET := loader
BPF_OBJ := traffic_mark.bpf.o
BPF_SKEL := traffic_mark.skel.h

# 自动探测架构 (x86_64 -> x86, aarch64 -> arm64)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

all: $(TARGET)

# 1. 编译内核态代码
$(BPF_OBJ): traffic_mark.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

# 2. 生成骨架头文件
$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 3. 编译用户态加载器 (需要安装 libbpf-dev)
$(TARGET): loader.cpp $(BPF_SKEL)
	g++ -O2 -Wall loader.cpp -lbpf -lelf -lz -o $@

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(TARGET)