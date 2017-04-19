package info.novatec.testit;

/**
 *
 */
@SuppressWarnings("ALL")
public class ZapScannerConfiguration {

    private String baseUrl = "";
    private String apiKey = "";
    private String targetHost = "";
    private String proxyPort = "";
    private String policy = "";
    private boolean spider;
    private boolean inScopeOnly;

    /**
     * Constructor.
     */
    public ZapScannerConfiguration() {
    }

    /**
     * Constructor.
     *
     * @param baseUrl base url to scan
     * @param apiKey api key to authorize scan
     * @param targetHost target host to scan
     * @param proxyPort proxy port
     * @param policy policy for scanning
     * @param inScopeOnly scan only in scope
     * @param spider spider target url first
     */
    public ZapScannerConfiguration(String baseUrl, String apiKey, String targetHost, String proxyPort, String policy, boolean inScopeOnly, boolean spider) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.targetHost = targetHost;
        this.proxyPort = proxyPort;
        this.policy = policy;
        this.inScopeOnly = inScopeOnly;
        this.spider = spider;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        this.targetHost = targetHost;
    }

    public String getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(String proxyPort) {
        this.proxyPort = proxyPort;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public boolean isInScopeOnly() {
        return inScopeOnly;
    }

    public void setInScopeOnly(boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly;
    }

    public boolean isSpider() {
        return spider;
    }
}
