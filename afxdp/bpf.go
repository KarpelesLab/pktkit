//go:build linux

package afxdp

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// eBPF instruction encoding (each instruction is 8 bytes).
type bpfInsn struct {
	code uint8  // opcode
	regs uint8  // dst_reg:4 | src_reg:4
	off  int16  // offset
	imm  int32  // immediate value
}

func bpfInsnBytes(insns []bpfInsn) []byte {
	buf := make([]byte, len(insns)*8)
	for i, insn := range insns {
		off := i * 8
		buf[off] = insn.code
		buf[off+1] = insn.regs
		binary.LittleEndian.PutUint16(buf[off+2:off+4], uint16(insn.off))
		binary.LittleEndian.PutUint32(buf[off+4:off+8], uint32(insn.imm))
	}
	return buf
}

// eBPF opcode helpers
const (
	// Instruction classes
	bpfClassLD  = unix.BPF_LD
	bpfClassLDX = unix.BPF_LDX
	bpfClassALU = 0x04
	bpfClassJMP = unix.BPF_JMP
	bpfClassALU64 = unix.BPF_ALU64

	// Size
	bpfSizeW  = unix.BPF_W  // 32-bit
	bpfSizeDW = unix.BPF_DW // 64-bit

	// Modes
	bpfModeIMM = unix.BPF_IMM
	bpfModeMEM = unix.BPF_MEM

	// Source
	bpfSrcK = unix.BPF_K // immediate
	bpfSrcX = unix.BPF_X // register

	// ALU/JMP ops
	bpfOpMOV  = unix.BPF_MOV
	bpfOpCALL = unix.BPF_CALL
	bpfOpEXIT = unix.BPF_EXIT

	// BPF function IDs
	bpfFuncRedirectMap = 51
)

func bpfReg(dst, src uint8) uint8 {
	return (src << 4) | (dst & 0x0f)
}

// BPF_LD_MAP_FD: pseudo instruction to load a map fd (2 instructions)
func bpfLdMapFD(dst uint8, fd int) []bpfInsn {
	return []bpfInsn{
		{code: bpfClassLD | bpfSizeDW | bpfModeIMM, regs: bpfReg(dst, 1), imm: int32(fd)},
		{}, // second slot for 64-bit immediate (upper 32 bits = 0)
	}
}

// BPF_LDX_MEM: load from memory
func bpfLdxMem(size, dst, src uint8, off int16) bpfInsn {
	return bpfInsn{code: bpfClassLDX | size | bpfModeMEM, regs: bpfReg(dst, src), off: off}
}

// BPF_MOV64_REG: dst = src (64-bit)
func bpfMov64Reg(dst, src uint8) bpfInsn {
	return bpfInsn{code: bpfClassALU64 | bpfSrcX | bpfOpMOV, regs: bpfReg(dst, src)}
}

// BPF_MOV64_IMM: dst = imm (64-bit)
func bpfMov64Imm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfClassALU64 | bpfSrcK | bpfOpMOV, regs: bpfReg(dst, 0), imm: imm}
}

// BPF_EMIT_CALL: call helper function
func bpfCall(funcID int32) bpfInsn {
	return bpfInsn{code: bpfClassJMP | bpfSrcK | bpfOpCALL, imm: funcID}
}

// BPF_EXIT
func bpfExit() bpfInsn {
	return bpfInsn{code: bpfClassJMP | bpfOpEXIT}
}

// bpfSyscall wraps the bpf() syscall.
func bpfSyscall(cmd int, attr unsafe.Pointer, size uintptr) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	if errno != 0 {
		return -1, fmt.Errorf("bpf(%d): %w", cmd, errno)
	}
	return int(fd), nil
}

// createXSKMap creates a BPF_MAP_TYPE_XSKMAP with the given max entries.
func createXSKMap(maxEntries int) (int, error) {
	const bpfMapCreate = unix.BPF_MAP_CREATE
	const bpfMapTypeXSKMap = unix.BPF_MAP_TYPE_XSKMAP

	// struct bpf_attr for BPF_MAP_CREATE
	type bpfMapCreateAttr struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
	}

	attr := bpfMapCreateAttr{
		mapType:    uint32(bpfMapTypeXSKMap),
		keySize:    4,
		valueSize:  4,
		maxEntries: uint32(maxEntries),
	}

	return bpfSyscall(bpfMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}

// updateMap inserts a key-value pair into a BPF map.
func updateMap(mapFD int, key, value uint32) error {
	const bpfMapUpdateElem = unix.BPF_MAP_UPDATE_ELEM

	type bpfMapUpdateAttr struct {
		mapFD uint32
		_     uint32 // padding
		key   uint64 // pointer
		value uint64 // pointer
		flags uint64
	}

	k := key
	v := value
	attr := bpfMapUpdateAttr{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(unsafe.Pointer(&k))),
		value: uint64(uintptr(unsafe.Pointer(&v))),
	}

	_, err := bpfSyscall(bpfMapUpdateElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// loadXDPProgram creates an XSKMAP and loads a minimal XDP_REDIRECT BPF program.
// Returns the program fd and map fd. The caller must close both when done.
func loadXDPProgram(maxQueues int) (progFD, mapFD int, err error) {
	mapFD, err = createXSKMap(maxQueues)
	if err != nil {
		return -1, -1, fmt.Errorf("create XSKMAP: %w", err)
	}

	// Build the XDP program:
	//   r1 = xdp_md* (ctx, passed by kernel in r1)
	//   r2 = *(u32*)(r1 + 16)  // rx_queue_index
	//   r1 = map_fd            // LD_MAP_FD pseudo-insn (2 insns)
	//   r3 = 0                 // flags
	//   call bpf_redirect_map(map, key, flags)
	//   exit
	var insns []bpfInsn
	insns = append(insns,
		bpfLdxMem(bpfSizeW, unix.BPF_REG_2, unix.BPF_REG_1, 16), // r2 = ctx->rx_queue_index
	)
	insns = append(insns, bpfLdMapFD(unix.BPF_REG_1, mapFD)...) // r1 = map_fd (2 insns)
	insns = append(insns,
		bpfMov64Imm(unix.BPF_REG_3, 0),     // r3 = 0 (flags)
		bpfCall(bpfFuncRedirectMap),          // call bpf_redirect_map
		bpfExit(),                            // exit
	)

	insnBytes := bpfInsnBytes(insns)

	// License string (required for GPL-only helpers)
	license := []byte("GPL\x00")

	// Log buffer for verifier errors
	logBuf := make([]byte, 65536)

	// struct bpf_attr for BPF_PROG_LOAD
	type bpfProgLoadAttr struct {
		progType     uint32
		insnCnt      uint32
		insns        uint64 // pointer
		license      uint64 // pointer
		logLevel     uint32
		logSize      uint32
		logBuf       uint64 // pointer
		kernVersion  uint32
		progFlags    uint32
		progName     [16]byte
		progIfindex  uint32
		expectedType uint32
	}

	attr := bpfProgLoadAttr{
		progType: uint32(unix.BPF_PROG_TYPE_XDP),
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insnBytes[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
		logLevel: 1,
		logSize:  uint32(len(logBuf)),
		logBuf:   uint64(uintptr(unsafe.Pointer(&logBuf[0]))),
	}
	copy(attr.progName[:], "pktkit_xdp")

	progFD, err = bpfSyscall(unix.BPF_PROG_LOAD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		unix.Close(mapFD)
		// Include verifier log in error message
		logStr := string(logBuf[:clen(logBuf)])
		if logStr != "" {
			return -1, -1, fmt.Errorf("load XDP program: %w\nverifier: %s", err, logStr)
		}
		return -1, -1, fmt.Errorf("load XDP program: %w", err)
	}

	return progFD, mapFD, nil
}

// attachXDP attaches an XDP program to a network interface using netlink.
func attachXDP(ifindex, progFD int, flags uint32) error {
	// Use BPF_LINK_CREATE for newer kernels, fall back to netlink IFLA_XDP_FD.
	type bpfLinkCreateAttr struct {
		progFD     uint32
		targetFD   uint32 // not used for XDP
		attachType uint32
		flags      uint32
		// XDP-specific fields
		targetIfindex uint32
	}

	attr := bpfLinkCreateAttr{
		progFD:        uint32(progFD),
		attachType:    uint32(unix.BPF_XDP),
		targetIfindex: uint32(ifindex),
	}

	_, err := bpfSyscall(unix.BPF_LINK_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err == nil {
		return nil
	}

	// Fall back to netlink IFLA_XDP_FD
	return attachXDPNetlink(ifindex, progFD, flags)
}

// attachXDPNetlink attaches an XDP program via netlink RTM_SETLINK.
func attachXDPNetlink(ifindex, progFD int, flags uint32) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	// Build netlink message: RTM_SETLINK with IFLA_XDP nested attribute
	// containing IFLA_XDP_FD and IFLA_XDP_FLAGS.

	// IFLA_XDP_FD attribute (nested inside IFLA_XDP)
	xdpFDAttr := nlAttr(unix.IFLA_XDP_FD, nlUint32(uint32(progFD)))
	xdpFlagsAttr := nlAttr(unix.IFLA_XDP_FLAGS, nlUint32(flags))
	xdpNested := nlAttr(unix.IFLA_XDP|unix.NLA_F_NESTED, append(xdpFDAttr, xdpFlagsAttr...))

	// ifinfomsg header
	var ifinfo [16]byte // struct ifinfomsg
	ifinfo[0] = unix.AF_UNSPEC
	binary.LittleEndian.PutUint32(ifinfo[4:8], uint32(ifindex))

	payload := append(ifinfo[:], xdpNested...)

	// nlmsghdr
	msgLen := 16 + len(payload) // nlmsghdr is 16 bytes
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))   // nlmsg_len
	binary.LittleEndian.PutUint16(msg[4:6], unix.RTM_SETLINK) // nlmsg_type
	binary.LittleEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK) // nlmsg_flags
	binary.LittleEndian.PutUint32(msg[8:12], 1)               // nlmsg_seq
	copy(msg[16:], payload)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(sock, msg, 0, sa); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	// Read ACK
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	if n >= 20 {
		// Check for error in nlmsgerr
		errCode := int32(binary.LittleEndian.Uint32(buf[16:20]))
		if errCode != 0 {
			return fmt.Errorf("netlink RTM_SETLINK: errno %d", -errCode)
		}
	}

	return nil
}

// detachXDP removes any XDP program from the interface.
func detachXDP(ifindex int) error {
	return attachXDPNetlink(ifindex, -1, 0)
}

// updateXSKMap inserts a socket fd into the XSKMAP at the given queue index.
func updateXSKMap(mapFD, queueID, socketFD int) error {
	return updateMap(mapFD, uint32(queueID), uint32(socketFD))
}

// nlAttr builds a netlink attribute (NLA).
func nlAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	padded := (l + 3) &^ 3
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(l))
	binary.LittleEndian.PutUint16(buf[2:4], typ)
	copy(buf[4:], data)
	return buf
}

// nlUint32 encodes a uint32 for a netlink attribute.
func nlUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// clen returns the index of the first zero byte (C string length).
func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}
