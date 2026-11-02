package collector

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

func TestAssetsEmbeddedNonEmptyAndSymbols(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
		symbols []string
	}{
		{
			name:    "python_sitecustomize",
			path:    filepath.Join("assets", "python", "sitecustomize.py"),
			content: pythonSiteCustomizeSource,
			symbols: []string{
				"LLM_TRACER_PY_TLS_ACTIVE",
				"SSLObject",
				"SSLSocket",
				"HTTPConnection",
			},
		},
		{
			name:    "node_hook_cjs",
			path:    filepath.Join("assets", "node", "node_hook.cjs"),
			content: nodeHookCJSSource,
			symbols: []string{
				"__LLM_TRACER_NODE_HOOK_LOADED__",
				"LLM_TRACER_PY_TLS_ACTIVE",
				"TLSSocket",
			},
		},
		{
			name:    "c_ptrace_helper",
			path:    filepath.Join("assets", "c", "ptrace_helper.c"),
			content: ptraceHelperCSource,
			symbols: []string{
				"LLMT_MAGIC",
				"PTRACE_GET_SYSCALL_INFO",
				"process_vm_readv",
				"libllm_tracer_ssl.so",
			},
		},
		{
			name:    "c_ssl_hook",
			path:    filepath.Join("assets", "c", "ssl_hook.c"),
			content: sslHookCSource,
			symbols: []string{
				"SSL_write",
				"SSL_write_ex",
				"SSL_read",
				"SSL_read_ex",
				"LLM_TRACER_PY_TLS_ACTIVE",
			},
		},
		{
			name:    "java_agent_source",
			path:    filepath.Join("assets", "java", "LlmTracerAgent.java"),
			content: javaAgentSource,
			symbols: []string{
				"class LlmTracerAgent",
				"TapProxySelector",
				"premain",
				"agentmain",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.TrimSpace(tc.content) == "" {
				t.Fatalf("embedded asset %s is empty", tc.name)
			}
			diskBytes, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("read on-disk asset %s: %v", tc.path, err)
			}
			if string(diskBytes) != tc.content {
				t.Fatalf("embedded asset %s differs from on-disk %s", tc.name, tc.path)
			}
			for _, sym := range tc.symbols {
				if !strings.Contains(tc.content, sym) {
					t.Errorf("asset %s missing required symbol %q", tc.name, sym)
				}
			}
		})
	}
}

func TestAssetsToolchainSyntaxCheck(t *testing.T) {
	t.Run("python3_py_compile", func(t *testing.T) {
		pyBin, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("python3 not found in PATH")
		}
		tmpDir := t.TempDir()
		srcFile := filepath.Join(tmpDir, "sitecustomize.py")
		if err := os.WriteFile(srcFile, []byte(pythonSiteCustomizeSource), 0o644); err != nil {
			t.Fatalf("write temp python file: %v", err)
		}
		cmd := exec.Command(pyBin, "-m", "py_compile", srcFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("python3 -m py_compile failed: %v\n%s", err, string(out))
		}
	})

	t.Run("node_check", func(t *testing.T) {
		nodeBin, err := exec.LookPath("node")
		if err != nil {
			t.Skip("node not found in PATH")
		}
		tmpDir := t.TempDir()
		srcFile := filepath.Join(tmpDir, "node_hook.cjs")
		if err := os.WriteFile(srcFile, []byte(nodeHookCJSSource), 0o644); err != nil {
			t.Fatalf("write temp node file: %v", err)
		}
		cmd := exec.Command(nodeBin, "--check", srcFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("node --check failed: %v\n%s", err, string(out))
		}
	})

	t.Run("gcc_ssl_hook_syntax", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("ssl_hook.c uses POSIX headers not targeted at windows")
		}
		ccBin, err := exec.LookPath("gcc")
		if err != nil {
			t.Skip("gcc not found in PATH")
		}
		tmpDir := t.TempDir()
		srcFile := filepath.Join(tmpDir, "ssl_hook.c")
		if err := os.WriteFile(srcFile, []byte(sslHookCSource), 0o644); err != nil {
			t.Fatalf("write temp ssl_hook.c: %v", err)
		}
		cmd := exec.Command(ccBin, "-fsyntax-only", srcFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gcc -fsyntax-only ssl_hook.c failed: %v\n%s", err, string(out))
		}
	})

	t.Run("gcc_ptrace_helper_syntax", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("ptrace_helper.c is Linux-specific")
		}
		ccBin, err := exec.LookPath("gcc")
		if err != nil {
			t.Skip("gcc not found in PATH")
		}
		tmpDir := t.TempDir()
		srcFile := filepath.Join(tmpDir, "ptrace_helper.c")
		if err := os.WriteFile(srcFile, []byte(ptraceHelperCSource), 0o644); err != nil {
			t.Fatalf("write temp ptrace_helper.c: %v", err)
		}
		cmd := exec.Command(ccBin, "-fsyntax-only", srcFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gcc -fsyntax-only ptrace_helper.c failed: %v\n%s", err, string(out))
		}
	})

	t.Run("javac_syntax", func(t *testing.T) {
		javacBin, err := exec.LookPath("javac")
		if err != nil {
			t.Skip("javac not found in PATH")
		}
		tmpDir := t.TempDir()
		srcFile := filepath.Join(tmpDir, "LlmTracerAgent.java")
		if err := os.WriteFile(srcFile, []byte(javaAgentSource), 0o644); err != nil {
			t.Fatalf("write temp LlmTracerAgent.java: %v", err)
		}
		cmd := exec.Command(javacBin, "-Xlint:-options", "--release", "8", "-g:none", srcFile)
		cmd.Dir = tmpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("javac failed: %v\n%s", err, string(out))
		}
	})
}

func verifyClassHeaderAndSymbol(t *testing.T, name string, data []byte, expectedUTF8 []string) {
	t.Helper()
	if len(data) < 10 {
		t.Fatalf("%s too short: %d bytes", name, len(data))
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != 0xCAFEBABE {
		t.Fatalf("%s invalid magic: got 0x%08X, want 0xCAFEBABE", name, magic)
	}
	minor := binary.BigEndian.Uint16(data[4:6])
	major := binary.BigEndian.Uint16(data[6:8])
	if major != 52 || minor != 0 {
		t.Fatalf("%s invalid class version: got %d.%d, want 52.0 (Java 8)", name, major, minor)
	}
	for _, sym := range expectedUTF8 {
		if !bytes.Contains(data, []byte(sym)) {
			t.Errorf("%s constant pool missing symbol %q", name, sym)
		}
	}
}

func TestAssetsJavaBytecodeAudit(t *testing.T) {
	verifyClassHeaderAndSymbol(t, "LlmTracerAgent.class", javaAgentMainClassBytes, []string{
		"LlmTracerAgent",
		"LlmTracerAgent$TapProxySelector",
		"javax/net/ssl/X509ExtendedTrustManager",
		"premain",
		"agentmain",
	})
	verifyClassHeaderAndSymbol(t, "LlmTracerAgent$TapProxySelector.class", javaAgentSelectorClassBytes, []string{
		"LlmTracerAgent$TapProxySelector",
		"java/net/ProxySelector",
		"select",
		"connectFailed",
	})

	// Verify SHA-256 against assets/java/checksums.sha256
	checksumMap := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(javaAgentChecksumsSHA256), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			checksumMap[fields[1]] = fields[0]
		}
	}
	checkDigest := func(fileName string, raw []byte) {
		expectedHex, ok := checksumMap[fileName]
		if !ok {
			t.Fatalf("checksums.sha256 missing entry for %s", fileName)
		}
		sum := sha256.Sum256(raw)
		actualHex := hex.EncodeToString(sum[:])
		if actualHex != expectedHex {
			t.Fatalf("%s SHA-256 mismatch: got %s, want %s", fileName, actualHex, expectedHex)
		}
	}
	checkDigest("LlmTracerAgent.class", javaAgentMainClassBytes)
	checkDigest("LlmTracerAgent$TapProxySelector.class", javaAgentSelectorClassBytes)

	// When javac is present, compile LlmTracerAgent.java and verify bytecode equivalence
	javacBin, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac not found in PATH; skipping live compilation comparison")
	}
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "LlmTracerAgent.java")
	if err := os.WriteFile(srcFile, []byte(javaAgentSource), 0o644); err != nil {
		t.Fatalf("write temp java source: %v", err)
	}
	cmd := exec.Command(javacBin, "-Xlint:-options", "--release", "8", "-g:none", srcFile)
	cmd.Dir = tmpDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("javac compile failed: %v\n%s", err, string(out))
	}
	compiledMain, err := os.ReadFile(filepath.Join(tmpDir, "LlmTracerAgent.class"))
	if err != nil {
		t.Fatalf("read compiled LlmTracerAgent.class: %v", err)
	}
	compiledSel, err := os.ReadFile(filepath.Join(tmpDir, "LlmTracerAgent$TapProxySelector.class"))
	if err != nil {
		t.Fatalf("read compiled LlmTracerAgent$TapProxySelector.class: %v", err)
	}
	verifyClassHeaderAndSymbol(t, "compiled LlmTracerAgent.class", compiledMain, []string{
		"LlmTracerAgent",
		"LlmTracerAgent$TapProxySelector",
		"premain",
		"agentmain",
	})
	verifyClassHeaderAndSymbol(t, "compiled LlmTracerAgent$TapProxySelector.class", compiledSel, []string{
		"LlmTracerAgent$TapProxySelector",
		"java/net/ProxySelector",
	})
}

func TestEnsureRuntimeHooksAndFallbackJar(t *testing.T) {
	// 1. Test EnsureJavaAgentJar in JRE-only fallback mode (PATH without javac)
	t.Run("java_jar_jre_only_fallback", func(t *testing.T) {
		emptyBin := t.TempDir()
		t.Setenv("PATH", emptyBin)

		hooksDir := t.TempDir()
		jarPath, err := EnsureJavaAgentJar(hooksDir)
		if err != nil {
			t.Fatalf("EnsureJavaAgentJar fallback failed: %v", err)
		}
		zr, err := zip.OpenReader(jarPath)
		if err != nil {
			t.Fatalf("open generated jar: %v", err)
		}
		defer zr.Close()

		entries := make(map[string][]byte)
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open zip entry %s: %v", f.Name, err)
			}
			b, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Fatalf("read zip entry %s: %v", f.Name, err)
			}
			entries[f.Name] = b
		}
		if !bytes.Equal(entries["LlmTracerAgent.class"], javaAgentMainClassBytes) {
			t.Fatalf("LlmTracerAgent.class in fallback jar does not match embedded bytes")
		}
		if !bytes.Equal(entries["LlmTracerAgent$TapProxySelector.class"], javaAgentSelectorClassBytes) {
			t.Fatalf("LlmTracerAgent$TapProxySelector.class in fallback jar does not match embedded bytes")
		}
		if !strings.Contains(string(entries["META-INF/MANIFEST.MF"]), "Premain-Class: LlmTracerAgent") {
			t.Fatalf("MANIFEST.MF missing Premain-Class")
		}
	})

	// 2. Test EnsureRuntimeHooks
	t.Run("ensure_runtime_hooks", func(t *testing.T) {
		hooksDir := t.TempDir()
		paths, err := EnsureRuntimeHooks(hooksDir)
		if err != nil {
			t.Fatalf("EnsureRuntimeHooks failed: %v", err)
		}
		if paths.PyHookDir == "" || paths.NodeHookJS == "" || paths.JavaAgentJar == "" {
			t.Fatalf("unexpected empty hook paths: %+v", paths)
		}
	})
}

func TestEnsureJavaAgentJarChecksumTamperRebuild(t *testing.T) {
	emptyBin := t.TempDir()
	t.Setenv("PATH", emptyBin)

	baseDir := t.TempDir()
	hooksDir := filepath.Join(baseDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	mon, err := selfmon.NewMonitor(baseDir)
	if err != nil {
		t.Fatalf("new selfmon: %v", err)
	}
	defer func() { _ = mon.Close() }()

	jarPath, err := EnsureJavaAgentJar(hooksDir, mon)
	if err != nil {
		t.Fatalf("initial EnsureJavaAgentJar failed: %v", err)
	}
	expectedChecksums, err := parseJavaAgentChecksums()
	if err != nil {
		t.Fatalf("parseJavaAgentChecksums failed: %v", err)
	}
	if err := verifyJavaAgentJar(jarPath, expectedChecksums); err != nil {
		t.Fatalf("initial jar failed verification: %v", err)
	}

	// Re-running on an intact jar must reuse it without warnings.
	if _, err := EnsureJavaAgentJar(hooksDir, mon); err != nil {
		t.Fatalf("second EnsureJavaAgentJar on valid jar failed: %v", err)
	}
	if st := mon.Stats(); st.TotalWarn != 0 {
		t.Fatalf("expected 0 warnings for intact jar reuse, got %d", st.TotalWarn)
	}

	// 1. Overwrite jar with >512 bytes of non-zip garbage (previously bypassed size-only check).
	corruptRaw := bytes.Repeat([]byte("tampered-java-agent-bytes-"), 40) // 1040 bytes > 512
	if err := os.WriteFile(jarPath, corruptRaw, 0o644); err != nil {
		t.Fatalf("write corrupt raw jar: %v", err)
	}
	rebuiltPath, err := EnsureJavaAgentJar(hooksDir, mon)
	if err != nil {
		t.Fatalf("EnsureJavaAgentJar after raw corruption failed: %v", err)
	}
	if err := verifyJavaAgentJar(rebuiltPath, expectedChecksums); err != nil {
		t.Fatalf("rebuilt jar after raw corruption failed verification: %v", err)
	}
	if st := mon.Stats(); st.TotalWarn < 1 {
		t.Fatalf("expected selfmon warning after raw jar corruption, got %d", st.TotalWarn)
	}

	// 2. Tamper with LlmTracerAgent.class bytecode inside a valid >512B ZIP jar and call EnsureJavaAgentJar(hooksDir)
	// without passing mon explicitly (verifying on-disk selfmon fallback discovery).
	tamperedClass := append([]byte(nil), javaAgentMainClassBytes...)
	tamperedClass[len(tamperedClass)-1] ^= 0xFF
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatalf("create tampered zip jar: %v", err)
	}
	zw := zip.NewWriter(f)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"META-INF/MANIFEST.MF", []byte(javaAgentManifest)},
		{"LlmTracerAgent.class", tamperedClass},
		{"LlmTracerAgent$TapProxySelector.class", javaAgentSelectorClassBytes},
	} {
		w, err := zw.Create(entry.name)
		if err != nil {
			t.Fatalf("create entry %s: %v", entry.name, err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatalf("write entry %s: %v", entry.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close tampered jar file: %v", err)
	}
	if err := verifyJavaAgentJar(jarPath, expectedChecksums); err == nil {
		t.Fatalf("expected verifyJavaAgentJar to fail on tampered class bytes")
	}

	rebuiltPath2, err := EnsureJavaAgentJar(hooksDir, mon)
	if err != nil {
		t.Fatalf("EnsureJavaAgentJar after class tamper failed: %v", err)
	}
	if err := verifyJavaAgentJar(rebuiltPath2, expectedChecksums); err != nil {
		t.Fatalf("rebuilt jar after class tamper failed verification: %v", err)
	}
	events, err := mon.QueryEvents(selfmon.Query{Stage: selfmon.StageProbe, Status: selfmon.StatusWarn, Limit: 20})
	if err != nil {
		t.Fatalf("query selfmon events: %v", err)
	}
	foundVerifyWarn := false
	for _, ev := range events {
		if ev.Action == "verify_java_agent_jar" && strings.Contains(ev.Error, "sha256 mismatch") {
			foundVerifyWarn = true
			break
		}
	}
	if !foundVerifyWarn {
		t.Fatalf("expected verify_java_agent_jar sha256 mismatch warning in selfmon, got %+v", events)
	}
}
