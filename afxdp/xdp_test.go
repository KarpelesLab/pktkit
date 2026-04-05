//go:build linux

package afxdp

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("AF_XDP tests require root or CAP_NET_ADMIN+CAP_BPF")
	}
}

func TestSocketCreation(t *testing.T) {
	skipUnprivileged(t)

	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("socket(AF_XDP): %v", err)
	}
	unix.Close(fd)
}

func TestCreateXSKMap(t *testing.T) {
	skipUnprivileged(t)

	mapFD, err := createXSKMap(64)
	if err != nil {
		t.Fatalf("createXSKMap: %v", err)
	}
	defer unix.Close(mapFD)

	if mapFD < 0 {
		t.Fatal("invalid map fd")
	}
}

func TestLoadXDPProgram(t *testing.T) {
	skipUnprivileged(t)

	progFD, mapFD, err := loadXDPProgram(64)
	if err != nil {
		t.Fatalf("loadXDPProgram: %v", err)
	}
	defer unix.Close(progFD)
	defer unix.Close(mapFD)

	if progFD < 0 || mapFD < 0 {
		t.Fatal("invalid fds")
	}
}

func TestBPFInsnEncoding(t *testing.T) {
	// Verify that our BPF instruction encoding produces the right byte layout.
	insn := bpfMov64Imm(unix.BPF_REG_3, 0)
	buf := bpfInsnBytes([]bpfInsn{insn})
	if len(buf) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(buf))
	}
	// opcode = BPF_ALU64 | BPF_K | BPF_MOV = 0x07 | 0x00 | 0xb0 = 0xb7
	if buf[0] != 0xb7 {
		t.Fatalf("opcode = 0x%02x, want 0xb7", buf[0])
	}
	// dst_reg = R3 (0x03), src_reg = 0
	if buf[1] != 0x03 {
		t.Fatalf("regs = 0x%02x, want 0x03", buf[1])
	}
}

func TestBPFLdMapFD(t *testing.T) {
	insns := bpfLdMapFD(unix.BPF_REG_1, 42)
	if len(insns) != 2 {
		t.Fatalf("LD_MAP_FD should be 2 instructions, got %d", len(insns))
	}
	// First insn: BPF_LD | BPF_DW | BPF_IMM with src_reg=1 (pseudo)
	if insns[0].code != (bpfClassLD | bpfSizeDW | bpfModeIMM) {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", insns[0].code, bpfClassLD|bpfSizeDW|bpfModeIMM)
	}
	if insns[0].imm != 42 {
		t.Fatalf("imm = %d, want 42", insns[0].imm)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{Interface: "lo"}
	if cfg.RingSize == 0 {
		cfg.RingSize = defaultRingSize
	}
	if cfg.FrameSize == 0 {
		cfg.FrameSize = defaultFrameSize
	}
	if cfg.NumFrames == 0 {
		cfg.NumFrames = defaultNumFrames
	}

	if cfg.RingSize != 2048 {
		t.Fatalf("default RingSize = %d, want 2048", cfg.RingSize)
	}
	if cfg.FrameSize != 4096 {
		t.Fatalf("default FrameSize = %d, want 4096", cfg.FrameSize)
	}
}

func TestNewInvalidInterface(t *testing.T) {
	_, err := New(Config{Interface: "nonexistent_iface_xyz"})
	if err == nil {
		t.Fatal("expected error for nonexistent interface")
	}
}

func TestNewBadRingSize(t *testing.T) {
	_, err := New(Config{Interface: "lo", RingSize: 1000})
	if err == nil {
		t.Fatal("expected error for non-power-of-2 ring size")
	}
}

func TestDeviceOnLoopback(t *testing.T) {
	skipUnprivileged(t)

	dev, err := New(Config{
		Interface: "lo",
		QueueID:   0,
		Copy:      true,
		RingSize:  256,
		NumFrames: 512,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer dev.Close()

	if mac := dev.HWAddr(); mac == nil {
		t.Log("loopback has no MAC (expected)")
	}

	// Verify statistics are accessible
	stats, err := dev.Statistics()
	if err != nil {
		t.Fatalf("Statistics: %v", err)
	}
	_ = stats

	// Verify Done channel is open
	select {
	case <-dev.Done():
		t.Fatal("device should not be done yet")
	default:
	}

	// Close and verify Done is closed
	dev.Close()
	<-dev.Done()
}
