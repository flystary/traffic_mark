TARGET   := loader
BPF_OBJ  := traffic_mark.bpf.o
BPF_SKEL := traffic_mark.skel.h
BPF_MAP_PATH := /sys/fs/bpf/ip_marks

# 自动探测架构
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
HOST_ARCH := $(shell gcc -dumpmachine)

all: $(TARGET)

# 1. 编译内核态代码 (加入架构头文件路径)
$(BPF_OBJ): traffic_mark.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(HOST_ARCH) \
		-c $< -o $@

# 2. 生成骨架
$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 3. 编译用户态加载器
$(TARGET): loader.cpp $(BPF_SKEL)
	g++ -O2 -Wall $< -lbpf -lelf -lz -o $@

# 一键清理环境并运行
run: $(TARGET)
	@echo "清理旧的残留..."
	-sudo pkill -9 $(TARGET)
	-sudo rm -f $(BPF_MAP_PATH)
	@# 检查并重新挂载 bpffs 确保路径可见
	@if ! mount | grep -q "/sys/fs/bpf type bpf"; then \
		sudo mount -t bpf bpf /sys/fs/bpf; \
	fi
	sudo ./$(TARGET)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(TARGET)
