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
        install();
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        install();
    }

    public static void install() {
        try {
            String host = System.getenv("LLM_TRACER_PROXY_HOST");
            String portStr = System.getenv("LLM_TRACER_PROXY_PORT");
            if ((host == null || host.isEmpty()) && System.getenv("HTTPS_PROXY") != null) {
                URI u = URI.create(System.getenv("HTTPS_PROXY"));
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
                ProxySelector.setDefault(new TapProxySelector(host, port, ProxySelector.getDefault()));
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
	javaAgentMainClassB64     = "yv66vgAAADQAlAoAAgADBwAEDAAFAAYBACZqYXZheC9uZXQvc3NsL1g1MDlFeHRlbmRlZFRydXN0TWFuYWdlcgEABjxpbml0PgEAAygpVgoACAAJBwAKDAALAAYBAA5MbG1UcmFjZXJBZ2VudAEAB2luc3RhbGwIAA0BABVMTE1fVFJBQ0VSX1BST1hZX0hPU1QKAA8AEAcAEQwAEgATAQAQamF2YS9sYW5nL1N5c3RlbQEABmdldGVudgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CAAVAQAVTExNX1RSQUNFUl9QUk9YWV9QT1JUCgAXABgHABkMABoAGwEAEGphdmEvbGFuZy9TdHJpbmcBAAdpc0VtcHR5AQADKClaCAAdAQALSFRUUFNfUFJPWFkKAB8AIAcAIQwAIgAjAQAMamF2YS9uZXQvVVJJAQAGY3JlYXRlAQAiKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9uZXQvVVJJOwoAHwAlDAAmACcBAAdnZXRIb3N0AQAUKClMamF2YS9sYW5nL1N0cmluZzsKAB8AKQwAKgArAQAHZ2V0UG9ydAEAAygpSQoAFwAtDAAuAC8BAAd2YWx1ZU9mAQAVKEkpTGphdmEvbGFuZy9TdHJpbmc7CgAxADIHADMMADQANQEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIcGFyc2VJbnQBABUoTGphdmEvbGFuZy9TdHJpbmc7KUkIADcBAA5odHRwLnByb3h5SG9zdAoADwA5DAA6ADsBAAtzZXRQcm9wZXJ0eQEAOChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CAA9AQAOaHR0cC5wcm94eVBvcnQIAD8BAA9odHRwcy5wcm94eUhvc3QIAEEBAA9odHRwcy5wcm94eVBvcnQIAEMBABJodHRwLm5vblByb3h5SG9zdHMIAEUBAAAIAEcBACdqZGsuaHR0cC5hdXRoLnR1bm5lbGluZy5kaXNhYmxlZFNjaGVtZXMIAEkBADNqZGsuaW50ZXJuYWwuaHR0cGNsaWVudC5kaXNhYmxlSG9zdG5hbWVWZXJpZmljYXRpb24IAEsBAAR0cnVlBwBNAQAfTGxtVHJhY2VyQWdlbnQkVGFwUHJveHlTZWxlY3RvcgoATwBQBwBRDABSAFMBABZqYXZhL25ldC9Qcm94eVNlbGVjdG9yAQAKZ2V0RGVmYXVsdAEAGigpTGphdmEvbmV0L1Byb3h5U2VsZWN0b3I7CgBMAFUMAAUAVgEALihMamF2YS9sYW5nL1N0cmluZztJTGphdmEvbmV0L1Byb3h5U2VsZWN0b3I7KVYKAE8AWAwAWQBaAQAKc2V0RGVmYXVsdAEAGyhMamF2YS9uZXQvUHJveHlTZWxlY3RvcjspVgoACAADCABdAQADVExTCgBfAGAHAGEMAGIAYwEAGGphdmF4L25ldC9zc2wvU1NMQ29udGV4dAEAC2dldEluc3RhbmNlAQAuKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YXgvbmV0L3NzbC9TU0xDb250ZXh0OwcAZQEAGmphdmF4L25ldC9zc2wvVHJ1c3RNYW5hZ2VyBwBnAQAaamF2YS9zZWN1cml0eS9TZWN1cmVSYW5kb20KAGYAAwoAXwBqDABrAGwBAARpbml0AQBXKFtMamF2YXgvbmV0L3NzbC9LZXlNYW5hZ2VyO1tMamF2YXgvbmV0L3NzbC9UcnVzdE1hbmFnZXI7TGphdmEvc2VjdXJpdHkvU2VjdXJlUmFuZG9tOylWCgBfAG4MAFkAbwEAHShMamF2YXgvbmV0L3NzbC9TU0xDb250ZXh0OylWCgBfAHEMAHIAcwEAEGdldFNvY2tldEZhY3RvcnkBACIoKUxqYXZheC9uZXQvc3NsL1NTTFNvY2tldEZhY3Rvcnk7CgB1AHYHAHcMAHgAeQEAIGphdmF4L25ldC9zc2wvSHR0cHNVUkxDb25uZWN0aW9uAQAac2V0RGVmYXVsdFNTTFNvY2tldEZhY3RvcnkBACMoTGphdmF4L25ldC9zc2wvU1NMU29ja2V0RmFjdG9yeTspVgoAdQB7DAB8AH0BABpzZXREZWZhdWx0SG9zdG5hbWVWZXJpZmllcgEAIyhMamF2YXgvbmV0L3NzbC9Ib3N0bmFtZVZlcmlmaWVyOylWBwB/AQATamF2YS9sYW5nL1Rocm93YWJsZQcAgQEAImphdmEvc2VjdXJpdHkvY2VydC9YNTA5Q2VydGlmaWNhdGUHAIMBAB5qYXZheC9uZXQvc3NsL0hvc3RuYW1lVmVyaWZpZXIBAARDb2RlAQAHcHJlbWFpbgEAOyhMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL2luc3RydW1lbnQvSW5zdHJ1bWVudGF0aW9uOylWAQAJYWdlbnRtYWluAQANU3RhY2tNYXBUYWJsZQEAEmNoZWNrQ2xpZW50VHJ1c3RlZAEAOihbTGphdmEvc2VjdXJpdHkvY2VydC9YNTA5Q2VydGlmaWNhdGU7TGphdmEvbGFuZy9TdHJpbmc7KVYBABJjaGVja1NlcnZlclRydXN0ZWQBABJnZXRBY2NlcHRlZElzc3VlcnMBACcoKVtMamF2YS9zZWN1cml0eS9jZXJ0L1g1MDlDZXJ0aWZpY2F0ZTsBAEsoW0xqYXZhL3NlY3VyaXR5L2NlcnQvWDUwOUNlcnRpZmljYXRlO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL25ldC9Tb2NrZXQ7KVYBAFMoW0xqYXZhL3NlY3VyaXR5L2NlcnQvWDUwOUNlcnRpZmljYXRlO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZheC9uZXQvc3NsL1NTTEVuZ2luZTspVgEABnZlcmlmeQEALyhMamF2YS9sYW5nL1N0cmluZztMamF2YXgvbmV0L3NzbC9TU0xTZXNzaW9uOylaAQAMSW5uZXJDbGFzc2VzAQAQVGFwUHJveHlTZWxlY3RvcgAhAAgAAgABAIIAAAAMAAEABQAGAAEAhAAAABEAAQABAAAABSq3AAGxAAAAAAAJAIUAhgABAIQAAAAQAAAAAgAAAAS4AAexAAAAAAAJAIcAhgABAIQAAAAQAAAAAgAAAAS4AAexAAAAAAAJAAsABgABAIQAAAEEAAYABAAAANASDLgADksSFLgADkwqxgAKKrYAFpkAKBIcuAAOxgAgEhy4AA64AB5NLLYAJEsstgAongALLLYAKLgALEwqxgBdKrYAFpoAVivGAFIrtgAWmgBLK7gAMD0SNiq4ADhXEjwruAA4VxI+KrgAOFcSQCu4ADhXEkISRLgAOFcSRhJEuAA4VxJIEkq4ADhXuwBMWSocuABOtwBUuABXuwAIWbcAW00SXLgAXk4tAQS9AGRZAyxTuwBmWbcAaLYAaS24AG0ttgBwuAB0LLgAeqcABEuxAAEAAADLAM4AfgABAIgAAAAaAAX9ABcHABcHABck+wBd/wAzAAAAAQcAfgAAAQCJAIoAAQCEAAAADQAAAAMAAAABsQAAAAAAAQCLAIoAAQCEAAAADQAAAAMAAAABsQAAAAAAAQCMAI0AAQCEAAAAEQABAAEAAAAFA70AgLAAAAAAAAEAiQCOAAEAhAAAAA0AAAAEAAAAAbEAAAAAAAEAiwCOAAEAhAAAAA0AAAAEAAAAAbEAAAAAAAEAiQCPAAEAhAAAAA0AAAAEAAAAAbEAAAAAAAEAiwCPAAEAhAAAAA0AAAAEAAAAAbEAAAAAAAEAkACRAAEAhAAAAA4AAQADAAAAAgSsAAAAAAABAJIAAAAKAAEATAAIAJMAGQ=="
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
