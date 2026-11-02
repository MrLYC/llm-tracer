package collector

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParseTracepointFormat(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]int16
		wantErr bool
	}{
		{
			name: "sys_enter_write",
			content: `name: sys_enter_write
ID: 725
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:const char * buf;	offset:24;	size:8;	signed:0;
	field:size_t count;	offset:32;	size:8;	signed:0;
`,
			want: map[string]int16{
				"common_type": 0, "common_flags": 2, "__syscall_nr": 8,
				"fd": 16, "buf": 24, "count": 32,
			},
		},
		{
			name: "sys_enter_writev",
			content: `field:long __syscall_nr;	offset:8;	size:8;	signed:1;
field:unsigned int fd;	offset:16;	size:8;	signed:0;
field:const struct iovec * vec;	offset:24;	size:8;	signed:0;
field:size_t vlen;	offset:32;	size:8;	signed:0;
`,
			want: map[string]int16{"__syscall_nr": 8, "fd": 16, "vec": 24, "vlen": 32},
		},
		{
			name: "sys_exit_read",
			content: `field:long __syscall_nr;	offset:8;	size:8;	signed:1;
field:long ret;	offset:16;	size:8;	signed:1;
`,
			want: map[string]int16{"__syscall_nr": 8, "ret": 16},
		},
		{name: "empty", content: "", wantErr: true},
		{name: "malformed", content: "field:broken\noffset:not-a-number", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTracepointFormat(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTracepointFormat: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("fields = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestGoVersionRegisterABISupport(t *testing.T) {
	cases := []struct {
		version string
		goarch  string
		want    bool
	}{
		{"go1.16.15", "amd64", false},
		{"go1.17.13", "amd64", true},
		{"go1.17", "arm64", false},
		{"go1.18.10", "arm64", true},
		{"go1.26.5", "amd64", true},
		{"go1.26.5", "arm64", true},
		{"go1.26.5", "riscv64", false},
		{"", "amd64", false},
	}
	for _, tc := range cases {
		if got := SupportsGoRegisterABI(tc.version, tc.goarch); got != tc.want {
			t.Errorf("SupportsGoRegisterABI(%q, %q) = %v, want %v", tc.version, tc.goarch, got, tc.want)
		}
	}
	if major, minor, ok := ParseGoVersionMajorMinor("go1.26.5"); !ok || major != 1 || minor != 26 {
		t.Errorf("ParseGoVersionMajorMinor = %d, %d, %v", major, minor, ok)
	}
}

func TestScanAMD64AndARM64PrologueAndRetPatterns(t *testing.T) {
	amdPrologues := []struct {
		name string
		code []byte
		want uint64
	}{
		{"stack-split-push-rbp", append([]byte{0x64, 0x48, 0x8b, 0x0c, 0x25, 0xf8, 0xff, 0xff, 0xff}, []byte{0x48, 0x3b, 0x61, 0x10, 0x76, 0x10, 0x55, 0x48, 0x89, 0xe5}...), 15},
		{"large-frame-imm8", []byte{0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x6c, 0x24, 0x08}, 4},
		{"large-frame-imm32", []byte{0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00, 0x48, 0x89, 0x6c, 0x24, 0x10}, 7},
	}
	for _, tc := range amdPrologues {
		if got := scanAMD64GoPrologueOffset(tc.code); got != tc.want {
			t.Errorf("%s: offset = %d, want %d", tc.name, got, tc.want)
		}
	}

	armCode := make([]byte, 12)
	binary.LittleEndian.PutUint32(armCode[0:], 0xf9400142)
	binary.LittleEndian.PutUint32(armCode[4:], 0xa9807bfd) // STP X29, X30, [SP,#-16]!
	if got := scanARM64GoPrologueOffset(armCode); got != 4 {
		t.Errorf("ARM64 STP prologue offset = %d, want 4", got)
	}
	armCode = make([]byte, 8)
	binary.LittleEndian.PutUint32(armCode[0:], 0xf81f83fd)
	binary.LittleEndian.PutUint32(armCode[4:], 0xd10023fd)
	if got := scanARM64GoPrologueOffset(armCode); got != 0 {
		t.Errorf("ARM64 MOVD/SUB prologue offset = %d, want 0", got)
	}

	retCases := []struct {
		name string
		code []byte
		want []uint64
	}{
		{"add-pop-ret", []byte{0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3}, []uint64{5}},
		{"add32-pop-ret", []byte{0x48, 0x81, 0xc4, 0x00, 0x01, 0x00, 0x00, 0x5d, 0xc3}, []uint64{8}},
		{"pop-add-ret", []byte{0x5d, 0x48, 0x83, 0xc4, 0x20, 0xc3}, []uint64{5}},
		{"pop-add32-ret", []byte{0x5d, 0x48, 0x81, 0xc4, 0x00, 0x01, 0x00, 0x00, 0xc3}, []uint64{8}},
		{"leave-ret", []byte{0xc9, 0xc3}, []uint64{1}},
		{"add-ret-no-fp", []byte{0x48, 0x83, 0xc4, 0x20, 0xc3}, []uint64{4}},
		{"add32-ret-no-fp", []byte{0x48, 0x81, 0xc4, 0x00, 0x01, 0x00, 0x00, 0xc3}, []uint64{7}},
		{"no-immediate-false-positive", []byte{0xb8, 0xc3, 0x00, 0x00, 0x00, 0xc9}, nil},
	}
	for _, tc := range retCases {
		if got := scanAMD64ReturnOffsets(tc.code); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: offsets = %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

func TestInspectGoTLSTarget_DWARFAndGopclntabFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Go toolchain build")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain unavailable")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("unsupported test architecture")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	binary := filepath.Join(dir, "tlsprobe")
	sourceCode := `package main

import (
	"context"
	"crypto/tls"
)

var conn *tls.Conn
var sink []byte

func main() {
	if conn != nil {
		_, _ = conn.Write(nil)
		_, _ = conn.Read(nil)
		_ = conn.HandshakeContext(context.Background())
	}
	_ = sink
}
`
	if err := os.WriteFile(source, []byte(sourceCode), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goTool, "build", "-gcflags=all=-N -l", "-ldflags=-s", "-o", binary, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe binary: %v\n%s", err, output)
	}

	target, err := InspectGoTLSTarget(binary)
	if err != nil {
		t.Fatalf("InspectGoTLSTarget: %v", err)
	}
	for _, name := range []string{"crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext"} {
		if target.Symbols[name] == 0 {
			t.Errorf("missing symbol %q; symbols=%#v", name, target.Symbols)
		}
	}
	if !strings.Contains(target.Note, "DWARF") && target.Note != "" {
		t.Logf("target note: %s", target.Note)
	}
}
