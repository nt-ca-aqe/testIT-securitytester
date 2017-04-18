package info.novatec.testit;

/**
 *
 */
@SuppressWarnings("ALL")
class ZapScannerConfiguration {

    private String baseUrl = "";
    private String apiKey = "";
    private String targetHost = "";
    private String proxyPort = "";
    private String policy = "";
    private boolean inScopeOnly;

    ZapScannerConfiguration() {
    }

    ZapScannerConfiguration(String baseUrl, String apiKey, String targetHost, String proxyPort, String policy, boolean inScopeOnly) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.targetHost = targetHost;
        this.proxyPort = proxyPort;
        this.policy = policy;
        this.inScopeOnly = inScopeOnly;
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
}