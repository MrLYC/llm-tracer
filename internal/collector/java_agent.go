package collector

import (
	"archive/zip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

//go:embed assets/java/LlmTracerAgent.java
var javaAgentSource string

// Pre-compiled Java 8 bytecode (version 52.0) fallback for JRE-only environments without javac.
//
//go:embed assets/java/LlmTracerAgent.class
var javaAgentMainClassBytes []byte

//go:embed assets/java/LlmTracerAgent$TapProxySelector.class
var javaAgentSelectorClassBytes []byte

//go:embed assets/java/checksums.sha256
var javaAgentChecksumsSHA256 string

const javaAgentManifest = "Manifest-Version: 1.0\r\n" +
	"Premain-Class: LlmTracerAgent\r\n" +
	"Agent-Class: LlmTracerAgent\r\n" +
	"Can-Redefine-Classes: false\r\n" +
	"Can-Retransform-Classes: false\r\n\r\n"

func parseJavaAgentChecksums() (map[string]string, error) {
	checksums := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(javaAgentChecksumsSHA256), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed java agent checksum line: %q", line)
		}
		digest := strings.ToLower(strings.TrimSpace(fields[0]))
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		checksums[name] = digest
	}
	if len(checksums) == 0 {
		return nil, fmt.Errorf("embedded java agent checksums are empty")
	}
	return checksums, nil
}

func verifyClassDigest(className string, data []byte, expectedChecksums map[string]string) error {
	wantHex, ok := expectedChecksums[className]
	if !ok {
		return fmt.Errorf("missing expected checksum for %s", className)
	}
	sum := sha256.Sum256(data)
	gotHex := hex.EncodeToString(sum[:])
	if gotHex != wantHex {
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", className, gotHex, wantHex)
	}
	return nil
}

// verifyJavaAgentJar validates that jarPath is a valid ZIP/JAR containing the expected MANIFEST.MF
// and class files whose SHA-256 digests match embedded assets/java/checksums.sha256.
func verifyJavaAgentJar(jarPath string, expectedChecksums map[string]string) error {
	st, err := os.Stat(jarPath)
	if err != nil {
		return err
	}
	if st.Size() <= 512 {
		return fmt.Errorf("java agent jar %s is truncated (%d bytes <= 512)", jarPath, st.Size())
	}
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return fmt.Errorf("open java agent jar zip: %w", err)
	}
	defer zr.Close()

	entries := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open jar entry %s: %w", f.Name, err)
		}
		b, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return fmt.Errorf("read jar entry %s: %w", f.Name, readErr)
		}
		entries[f.Name] = b
	}

	manifest, ok := entries["META-INF/MANIFEST.MF"]
	if !ok {
		return fmt.Errorf("java agent jar missing META-INF/MANIFEST.MF")
	}
	if string(manifest) != javaAgentManifest {
		return fmt.Errorf("java agent jar META-INF/MANIFEST.MF content mismatch")
	}

	for name := range entries {
		if name == "META-INF/MANIFEST.MF" {
			continue
		}
		if _, ok := expectedChecksums[name]; !ok {
			return fmt.Errorf("java agent jar contains unexpected entry %q", name)
		}
	}

	for className := range expectedChecksums {
		raw, ok := entries[className]
		if !ok {
			return fmt.Errorf("java agent jar missing required class %s", className)
		}
		if err := verifyClassDigest(className, raw, expectedChecksums); err != nil {
			return err
		}
	}
	return nil
}

func recordJavaAgentVerifyFailure(hooksDir, jarPath string, verifyErr error, mons ...*selfmon.Monitor) {
	detail := map[string]any{
		"jar_path": jarPath,
		"action":   "rebuild_java_agent_jar",
	}
	explicitRecorded := false
	for _, m := range mons {
		if m != nil {
			m.RecordWarn(selfmon.StageProbe, "verify_java_agent_jar", verifyErr.Error(), detail)
			explicitRecorded = true
		}
	}
	if explicitRecorded {
		return
	}
	if m := lastCollectorMonitor.Load(); m != nil {
		m.RecordWarn(selfmon.StageProbe, "verify_java_agent_jar", verifyErr.Error(), detail)
	}
	for _, candidateDir := range []string{hooksDir, filepath.Dir(hooksDir)} {
		if candidateDir == "" {
			continue
		}
		if fi, err := os.Stat(filepath.Join(candidateDir, "selfmon")); err == nil && fi.IsDir() {
			if m, err := selfmon.NewMonitor(candidateDir); err == nil {
				m.RecordWarn(selfmon.StageProbe, "verify_java_agent_jar", verifyErr.Error(), detail)
				_ = m.Close()
				break
			}
		}
	}
}

// EnsureJavaAgentJar builds or unpacks llm_tracer_java.jar in hooksDir for zero-code JVM capture via JAVA_TOOL_OPTIONS.
// If an existing jar is present on disk, its contents are verified against embedded assets/java/checksums.sha256
// and rebuilt if tampered or corrupted.
func EnsureJavaAgentJar(hooksDir string, mons ...*selfmon.Monitor) (string, error) {
	expectedChecksums, err := parseJavaAgentChecksums()
	if err != nil {
		return "", err
	}

	jarPath := filepath.Join(hooksDir, "llm_tracer_java.jar")
	if fi, err := os.Lstat(jarPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("refusing to use or overwrite symlink or non-regular java agent jar: %s", jarPath)
		}
		if verifyErr := verifyJavaAgentJar(jarPath, expectedChecksums); verifyErr == nil {
			_ = chmodArtifactNoFollow(jarPath, 0o644)
			return jarPath, nil
		} else {
			recordJavaAgentVerifyFailure(hooksDir, jarPath, verifyErr, mons...)
			_ = os.Remove(jarPath)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}

	var mainClassBytes, selClassBytes []byte
	buildDir := filepath.Join(hooksDir, "java_build")
	if err := ensureSafeSubDir(buildDir, 0o755); err != nil {
		return "", err
	}
	srcPath := filepath.Join(buildDir, "LlmTracerAgent.java")
	if err := writeArtifactNoFollow(srcPath, []byte(javaAgentSource), 0o644); err != nil {
		return "", err
	}

	if javacPath, err := exec.LookPath("javac"); err == nil {
		cmd := exec.Command(javacPath, "-Xlint:-options", "--release", "8", "-g:none", srcPath)
		cmd.Dir = buildDir
		if err := cmd.Run(); err == nil {
			mainClassBytes, _ = os.ReadFile(filepath.Join(buildDir, "LlmTracerAgent.class"))
			selClassBytes, _ = os.ReadFile(filepath.Join(buildDir, "LlmTracerAgent$TapProxySelector.class"))
			if verifyClassDigest("LlmTracerAgent.class", mainClassBytes, expectedChecksums) != nil ||
				verifyClassDigest("LlmTracerAgent$TapProxySelector.class", selClassBytes, expectedChecksums) != nil {
				mainClassBytes = nil
				selClassBytes = nil
			}
		}
	}
	if len(mainClassBytes) == 0 || len(selClassBytes) == 0 {
		if len(javaAgentMainClassBytes) == 0 || len(javaAgentSelectorClassBytes) == 0 {
			return "", fmt.Errorf("embedded Java agent fallback bytecode is empty")
		}
		if err := verifyClassDigest("LlmTracerAgent.class", javaAgentMainClassBytes, expectedChecksums); err != nil {
			return "", err
		}
		if err := verifyClassDigest("LlmTracerAgent$TapProxySelector.class", javaAgentSelectorClassBytes, expectedChecksums); err != nil {
			return "", err
		}
		mainClassBytes = javaAgentMainClassBytes
		selClassBytes = javaAgentSelectorClassBytes
	}

	f, err := createArtifactFileNoFollow(jarPath, 0o644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	writeEntry := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	if err := writeEntry("META-INF/MANIFEST.MF", []byte(javaAgentManifest)); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := writeEntry("LlmTracerAgent.class", mainClassBytes); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := writeEntry("LlmTracerAgent$TapProxySelector.class", selClassBytes); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := chmodArtifactNoFollow(jarPath, 0o644); err != nil {
		return "", err
	}
	if err := verifyJavaAgentJar(jarPath, expectedChecksums); err != nil {
		return "", fmt.Errorf("verify newly built java agent jar: %w", err)
	}
	return jarPath, nil
}
