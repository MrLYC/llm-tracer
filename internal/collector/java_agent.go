package collector

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const javaAgentSource = `import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

public class LlmTracerAgent extends X509ExtendedTrustManager implements HostnameVerifier {
    public static final class TapProxySelector extends ProxySelector {
        private final String host;
        private final int port;
        private final Proxy proxy;
        private final ProxySelector fallback;

        public TapProxySelector(String host, int port, ProxySelector fallback) {
            this.host = host;
            this.port = port;
            this.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
            this.fallback = fallback;
        }

        @Override
        public List<Proxy> select(URI uri) {
            if (uri == null) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            String scheme = uri.getScheme();
            if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                if (host.equals(uri.getHost()) && uri.getPort() == port) {
                    return Collections.singletonList(Proxy.NO_PROXY);
                }
                return Collections.singletonList(proxy);
            }
            return fallback != null ? fallback.select(uri) : Collections.singletonList(Proxy.NO_PROXY);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            if (fallback != null) {
                fallback.connectFailed(uri, sa, ioe);
            }
        }
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        install(agentArgs);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        install(agentArgs);
    }

    public static void install(String agentArgs) {
        try {
            String host = System.getenv("LLM_TRACER_PROXY_HOST");
            String portStr = System.getenv("LLM_TRACER_PROXY_PORT");
            String proxyUri = (agentArgs != null && !agentArgs.trim().isEmpty())
                ? agentArgs.trim()
                : System.getenv("HTTPS_PROXY");
            if ((host == null || host.isEmpty()) && proxyUri != null && !proxyUri.isEmpty()) {
                URI u = URI.create(proxyUri.contains("://") ? proxyUri : ("http://" + proxyUri));
                host = u.getHost();
                if (u.getPort() > 0) {
                    portStr = String.valueOf(u.getPort());
                }
            }
            if (host != null && !host.isEmpty() && portStr != null && !portStr.isEmpty()) {
                int port = Integer.parseInt(portStr);
                System.setProperty("http.proxyHost", host);
                System.setProperty("http.proxyPort", portStr);
                System.setProperty("https.proxyHost", host);
                System.setProperty("https.proxyPort", portStr);
                System.setProperty("http.nonProxyHosts", "");
                System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
                System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
                ProxySelector current = ProxySelector.getDefault();
                if (current instanceof TapProxySelector) {
                    ProxySelector.setDefault(new TapProxySelector(host, port, null));
                } else {
                    ProxySelector.setDefault(new TapProxySelector(host, port, current));
                }
            }

            LlmTracerAgent tm = new LlmTracerAgent();
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{tm}, new SecureRandom());
            SSLContext.setDefault(ctx);
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(tm);
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    @Override
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
    @Override
    public boolean verify(String hostname, SSLSession session) { return true; }
}
`

// Pre-compiled Java 8 bytecode (version 52.0) fallback for JRE-only environments without javac.
const (
	javaAgentMainClassB64     = "yv66vgAAADQAqgoAAgADBwAEDAAFAAYBACZqYXZheC9uZXQvc3NsL1g1MDlFeHRlbmRlZFRydXN0TWFuYWdlcgEABjxpbml0PgEAAygpVgoACAAJBwAKDAALAAwBAA5MbG1UcmFjZXJBZ2VudAEAB2luc3RhbGwBABUoTGphdmEvbGFuZy9TdHJpbmc7KVYIAA4BABVMTE1fVFJBQ0VSX1BST1hZX0hPU1QKABAAEQcAEgwAEwAUAQAQamF2YS9sYW5nL1N5c3RlbQEABmdldGVudgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CAAWAQAVTExNX1RSQUNFUl9QUk9YWV9QT1JUCgAYABkHABoMABsAHAEAEGphdmEvbGFuZy9TdHJpbmcBAAR0cmltAQAUKClMamF2YS9sYW5nL1N0cmluZzsKABgAHgwAHwAgAQAHaXNFbXB0eQEAAygpWggAIgEAC0hUVFBTX1BST1hZCAAkAQADOi8vCgAYACYMACcAKAEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaBwAqAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKACkAAwgALQEAB2h0dHA6Ly8KACkALwwAMAAxAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7CgApADMMADQAHAEACHRvU3RyaW5nCgA2ADcHADgMADkAOgEADGphdmEvbmV0L1VSSQEABmNyZWF0ZQEAIihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbmV0L1VSSTsKADYAPAwAPQAcAQAHZ2V0SG9zdAoANgA/DABAAEEBAAdnZXRQb3J0AQADKClJCgAYAEMMAEQARQEAB3ZhbHVlT2YBABUoSSlMamF2YS9sYW5nL1N0cmluZzsKAEcASAcASQwASgBLAQARamF2YS9sYW5nL0ludGVnZXIBAAhwYXJzZUludAEAFShMamF2YS9sYW5nL1N0cmluZzspSQgATQEADmh0dHAucHJveHlIb3N0CgAQAE8MAFAAUQEAC3NldFByb3BlcnR5AQA4KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsIAFMBAA5odHRwLnByb3h5UG9ydAgAVQEAD2h0dHBzLnByb3h5SG9zdAgAVwEAD2h0dHBzLnByb3h5UG9ydAgAWQEAEmh0dHAubm9uUHJveHlIb3N0cwgAWwEAAAgAXQEAJ2pkay5odHRwLmF1dGgudHVubmVsaW5nLmRpc2FibGVkU2NoZW1lcwgAXwEAM2pkay5pbnRlcm5hbC5odHRwY2xpZW50LmRpc2FibGVIb3N0bmFtZVZlcmlmaWNhdGlvbggAYQEABHRydWUKAGMAZAcAZQwAZgBnAQAWamF2YS9uZXQvUHJveHlTZWxlY3RvcgEACmdldERlZmF1bHQBABooKUxqYXZhL25ldC9Qcm94eVNlbGVjdG9yOwcAaQEAH0xsbVRyYWNlckFnZW50JFRhcFByb3h5U2VsZWN0b3IKAGgAawwABQBsAQAuKExqYXZhL2xhbmcvU3RyaW5nO0lMamF2YS9uZXQvUHJveHlTZWxlY3RvcjspVgoAYwBuDABvAHABAApzZXREZWZhdWx0AQAbKExqYXZhL25ldC9Qcm94eVNlbGVjdG9yOylWCgAIAAMIAHMBAANUTFMKAHUAdgcAdwwAeAB5AQAYamF2YXgvbmV0L3NzbC9TU0xDb250ZXh0AQALZ2V0SW5zdGFuY2UBAC4oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZheC9uZXQvc3NsL1NTTENvbnRleHQ7BwB7AQAaamF2YXgvbmV0L3NzbC9UcnVzdE1hbmFnZXIHAH0BABpqYXZhL3NlY3VyaXR5L1NlY3VyZVJhbmRvbQoAfAADCgB1AIAMAIEAggEABGluaXQBAFcoW0xqYXZheC9uZXQvc3NsL0tleU1hbmFnZXI7W0xqYXZheC9uZXQvc3NsL1RydXN0TWFuYWdlcjtMamF2YS9zZWN1cml0eS9TZWN1cmVSYW5kb207KVYKAHUAhAwAbwCFAQAdKExqYXZheC9uZXQvc3NsL1NTTENvbnRleHQ7KVYKAHUAhwwAiACJAQAQZ2V0U29ja2V0RmFjdG9yeQEAIigpTGphdmF4L25ldC9zc2wvU1NMU29ja2V0RmFjdG9yeTsKAIsAjAcAjQwAjgCPAQAgamF2YXgvbmV0L3NzbC9IdHRwc1VSTENvbm5lY3Rpb24BABpzZXREZWZhdWx0U1NMU29ja2V0RmFjdG9yeQEAIyhMamF2YXgvbmV0L3NzbC9TU0xTb2NrZXRGYWN0b3J5OylWCgCLAJEMAJIAkwEAGnNldERlZmF1bHRIb3N0bmFtZVZlcmlmaWVyAQAjKExqYXZheC9uZXQvc3NsL0hvc3RuYW1lVmVyaWZpZXI7KVYHAJUBABNqYXZhL2xhbmcvVGhyb3dhYmxlBwCXAQAiamF2YS9zZWN1cml0eS9jZXJ0L1g1MDlDZXJ0aWZpY2F0ZQcAmQEAHmphdmF4L25ldC9zc2wvSG9zdG5hbWVWZXJpZmllcgEABENvZGUBAAdwcmVtYWluAQA7KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW5zdHJ1bWVudC9JbnN0cnVtZW50YXRpb247KVYBAAlhZ2VudG1haW4BAA1TdGFja01hcFRhYmxlAQASY2hlY2tDbGllbnRUcnVzdGVkAQA6KFtMamF2YS9zZWN1cml0eS9jZXJ0L1g1MDlDZXJ0aWZpY2F0ZTtMamF2YS9sYW5nL1N0cmluZzspVgEAEmNoZWNrU2VydmVyVHJ1c3RlZAEAEmdldEFjY2VwdGVkSXNzdWVycwEAJygpW0xqYXZhL3NlY3VyaXR5L2NlcnQvWDUwOUNlcnRpZmljYXRlOwEASyhbTGphdmEvc2VjdXJpdHkvY2VydC9YNTA5Q2VydGlmaWNhdGU7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbmV0L1NvY2tldDspVgEAUyhbTGphdmEvc2VjdXJpdHkvY2VydC9YNTA5Q2VydGlmaWNhdGU7TGphdmEvbGFuZy9TdHJpbmc7TGphdmF4L25ldC9zc2wvU1NMRW5naW5lOylWAQAGdmVyaWZ5AQAvKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZheC9uZXQvc3NsL1NTTFNlc3Npb247KVoBAAxJbm5lckNsYXNzZXMBABBUYXBQcm94eVNlbGVjdG9yACEACAACAAEAmAAAAAwAAQAFAAYAAQCaAAAAEQABAAEAAAAFKrcAAbEAAAAAAAkAmwCcAAEAmgAAABEAAQACAAAABSq4AAexAAAAAAAJAJ0AnAABAJoAAAARAAEAAgAAAAUquAAHsQAAAAAACQALAAwAAQCaAAABgAAGAAYAAAEzEg24AA9MEhW4AA9NKsYAFCq2ABe2AB2aAAoqtgAXpwAIEiG4AA9OK8YACiu2AB2ZAEotxgBGLbYAHZoAPy0SI7YAJZkABy2nABa7AClZtwArEiy2AC4ttgAutgAyuAA1OgQZBLYAO0wZBLYAPp4ADBkEtgA+uABCTSvGAHwrtgAdmgB1LMYAcSy2AB2aAGosuABGNgQSTCu4AE5XElIsuABOVxJUK7gATlcSViy4AE5XElgSWrgATlcSXBJauABOVxJeEmC4AE5XuABiOgUZBcEAaJkAFLsAaFkrFQQBtwBquABtpwASuwBoWSsVBBkFtwBquABtuwAIWbcAcToEEnK4AHQ6BRkFAQS9AHpZAxkEU7sAfFm3AH62AH8ZBbgAgxkFtgCGuACKGQS4AJCnAARMsQABAAABLgExAJQAAQCeAAAAMwAK/QAhBwAYBwAYRAcAGPwACwcAGBdSBwAYG/0AbQEHAGP5AA7/ADoAAQcAGAABBwCUAAABAJ8AoAABAJoAAAANAAAAAwAAAAGxAAAAAAABAKEAoAABAJoAAAANAAAAAwAAAAGxAAAAAAABAKIAowABAJoAAAARAAEAAQAAAAUDvQCWsAAAAAAAAQCfAKQAAQCaAAAADQAAAAQAAAABsQAAAAAAAQChAKQAAQCaAAAADQAAAAQAAAABsQAAAAAAAQCfAKUAAQCaAAAADQAAAAQAAAABsQAAAAAAAQChAKUAAQCaAAAADQAAAAQAAAABsQAAAAAAAQCmAKcAAQCaAAAADgABAAMAAAACBKwAAAAAAAEAqAAAAAoAAQBoAAgAqQAZ"
	javaAgentSelectorClassB64 = "yv66vgAAADQAYQoAAgADBwAEDAAFAAYBABZqYXZhL25ldC9Qcm94eVNlbGVjdG9yAQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEAH0xsbVRyYWNlckFnZW50JFRhcFByb3h5U2VsZWN0b3IBAARob3N0AQASTGphdmEvbGFuZy9TdHJpbmc7CQAIAA4MAA8AEAEABHBvcnQBAAFJBwASAQAOamF2YS9uZXQvUHJveHkJABQAFQcAFgwAFwAYAQATamF2YS9uZXQvUHJveHkkVHlwZQEABEhUVFABABVMamF2YS9uZXQvUHJveHkkVHlwZTsHABoBABpqYXZhL25ldC9JbmV0U29ja2V0QWRkcmVzcwoAGQAcDAAFAB0BABYoTGphdmEvbGFuZy9TdHJpbmc7SSlWCgARAB8MAAUAIAEAMChMamF2YS9uZXQvUHJveHkkVHlwZTtMamF2YS9uZXQvU29ja2V0QWRkcmVzczspVgkACAAiDAAjACQBAAVwcm94eQEAEExqYXZhL25ldC9Qcm94eTsJAAgAJgwAJwAoAQAIZmFsbGJhY2sBABhMamF2YS9uZXQvUHJveHlTZWxlY3RvcjsJABEAKgwAKwAkAQAITk9fUFJPWFkKAC0ALgcALwwAMAAxAQAVamF2YS91dGlsL0NvbGxlY3Rpb25zAQANc2luZ2xldG9uTGlzdAEAJChMamF2YS9sYW5nL09iamVjdDspTGphdmEvdXRpbC9MaXN0OwoAMwA0BwA1DAA2ADcBAAxqYXZhL25ldC9VUkkBAAlnZXRTY2hlbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwgAOQEABGh0dHAKADsAPAcAPQwAPgA/AQAQamF2YS9sYW5nL1N0cmluZwEAEGVxdWFsc0lnbm9yZUNhc2UBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoIAEEBAAVodHRwcwoAMwBDDABEADcBAAdnZXRIb3N0CgA7AEYMAEcASAEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgoAMwBKDABLAEwBAAdnZXRQb3J0AQADKClJCgACAE4MAE8AUAEABnNlbGVjdAEAIChMamF2YS9uZXQvVVJJOylMamF2YS91dGlsL0xpc3Q7CgACAFIMAFMAVAEADWNvbm5lY3RGYWlsZWQBAD4oTGphdmEvbmV0L1VSSTtMamF2YS9uZXQvU29ja2V0QWRkcmVzcztMamF2YS9pby9JT0V4Y2VwdGlvbjspVgEALihMamF2YS9sYW5nL1N0cmluZztJTGphdmEvbmV0L1Byb3h5U2VsZWN0b3I7KVYBAARDb2RlAQANU3RhY2tNYXBUYWJsZQcAWQEADmphdmEvdXRpbC9MaXN0AQAJU2lnbmF0dXJlAQAyKExqYXZhL25ldC9VUkk7KUxqYXZhL3V0aWwvTGlzdDxMamF2YS9uZXQvUHJveHk7PjsBAAxJbm5lckNsYXNzZXMHAF4BAA5MbG1UcmFjZXJBZ2VudAEAEFRhcFByb3h5U2VsZWN0b3IBAARUeXBlADEACAACAAAABAASAAsADAAAABIADwAQAAAAEgAjACQAAAASACcAKAAAAAMAAQAFAFUAAQBWAAAANwAIAAQAAAArKrcAASortQAHKhy1AA0quwARWbIAE7sAGVkrHLcAG7cAHrUAISottQAlsQAAAAAAAQBPAFAAAgBWAAAAhQACAAMAAABjK8cACrIAKbgALLArtgAyTRI4LLYAOpoADBJALLYAOpkAKyq0AAcrtgBCtgBFmQAVK7YASSq0AA2gAAqyACm4ACywKrQAIbgALLAqtAAlxgAOKrQAJSu2AE2nAAmyACm4ACywAAAAAQBXAAAAEAAGC/wAFgcAOx8HEUUHAFgAWgAAAAIAWwABAFMAVAABAFYAAAAnAAQABAAAABIqtAAlxgANKrQAJSssLbYAUbEAAAABAFcAAAADAAERAAEAXAAAABIAAgAIAF0AXwAZABQAEQBgQBk="
)

const javaAgentManifest = "Manifest-Version: 1.0\r\n" +
	"Premain-Class: LlmTracerAgent\r\n" +
	"Agent-Class: LlmTracerAgent\r\n" +
	"Can-Redefine-Classes: false\r\n" +
	"Can-Retransform-Classes: false\r\n\r\n"

// EnsureJavaAgentJar builds or unpacks llm_tracer_java.jar in hooksDir for zero-code JVM capture via JAVA_TOOL_OPTIONS.
func EnsureJavaAgentJar(hooksDir string) (string, error) {
	jarPath := filepath.Join(hooksDir, "llm_tracer_java.jar")
	if st, err := os.Stat(jarPath); err == nil && st.Size() > 512 {
		return jarPath, nil
	}

	var mainClassBytes, selClassBytes []byte
	buildDir := filepath.Join(hooksDir, "java_build")
	_ = os.MkdirAll(buildDir, 0o755)
	srcPath := filepath.Join(buildDir, "LlmTracerAgent.java")
	_ = os.WriteFile(srcPath, []byte(javaAgentSource), 0o644)

	if javacPath, err := exec.LookPath("javac"); err == nil {
		cmd := exec.Command(javacPath, "-Xlint:-options", "--release", "8", "-g:none", srcPath)
		cmd.Dir = buildDir
		if err := cmd.Run(); err == nil {
			mainClassBytes, _ = os.ReadFile(filepath.Join(buildDir, "LlmTracerAgent.class"))
			selClassBytes, _ = os.ReadFile(filepath.Join(buildDir, "LlmTracerAgent$TapProxySelector.class"))
		}
	}
	if len(mainClassBytes) == 0 || len(selClassBytes) == 0 {
		var err error
		mainClassBytes, err = base64.StdEncoding.DecodeString(javaAgentMainClassB64)
		if err != nil {
			return "", fmt.Errorf("decode LlmTracerAgent.class: %w", err)
		}
		selClassBytes, err = base64.StdEncoding.DecodeString(javaAgentSelectorClassB64)
		if err != nil {
			return "", fmt.Errorf("decode LlmTracerAgent$TapProxySelector.class: %w", err)
		}
	}

	f, err := os.Create(jarPath)
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
	return jarPath, nil
}
