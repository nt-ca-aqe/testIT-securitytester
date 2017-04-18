package info.novatec.testit;

import info.novatec.testit.security.zap.ZapScanner;
import info.novatec.testit.security.zap.ZapScannerImpl;
import org.apache.commons.lang3.StringUtils;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.Alert;

import java.util.List;

import static info.novatec.testit.AlertMatchers.containsNoHighRiskAlerts;
import static org.junit.Assert.assertThat;

/**
 * JUnit rule for adding feature to run security tests.
 */
@SuppressWarnings("ALL")
class ZapSecurityScan extends ExternalResource {

    private static final Logger LOGGER = LoggerFactory.getLogger ( ZapSecurityScan.class );

    private ZapScanner zapScanner;

    private String site;
    private String apiKey;
    private String targetHost;
    private String proxyPort;
    private String policy;
    private boolean inScopeOnly;


    ZapSecurityScan(String site, String apiKey, String targetHost, String proxyPort, String policy) {
        this.site = site;
        this.apiKey = apiKey;
        this.targetHost = targetHost;
        this.proxyPort = proxyPort;
        this.policy = StringUtils.isNotBlank ( policy ) ? policy : StringUtils.EMPTY;
    }

    ZapScanner createZapScanner() {
        return new ZapScannerImpl ( this.apiKey, this.targetHost, this.proxyPort );
    }

    ZapScanner getZapScanner() {
        return zapScanner;
    }


    @Override
    protected void before () throws Throwable {
        super.before ();
        LOGGER.info ( "Initializing security.zap scanner" );
        zapScanner = createZapScanner ();
    }

    @Override
    protected void after () {
        super.after ();
        LOGGER.info ( "Performing security scan using policy '{}'", this.policy );

        List<Alert> alerts = zapScanner.completeScan ( this.site , this.inScopeOnly, this.policy );

        LOGGER.debug ( "Security scan uncovered following alerts {}", alerts );

        assertThat ( "Tested workflow should have no high risk alerts", alerts, containsNoHighRiskAlerts () );

    }
}
