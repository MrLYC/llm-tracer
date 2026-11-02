import java.io.IOException;
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
