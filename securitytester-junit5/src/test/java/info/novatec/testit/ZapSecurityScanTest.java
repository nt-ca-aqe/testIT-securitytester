package info.novatec.testit;

import info.novatec.testit.security.zap.ZapScanner;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.zaproxy.clientapi.core.Alert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import java.util.List;

import info.novatec.testit.AlertMatchers.ContainsNoHighRiskAlertMatcher;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

/**
 * Unit test for security test with {@link ZapSecurityScanExtension}
 */
@SuppressWarnings("ALL")
@ExtendWith(ZapSecurityScanExtension.class)
class ZapSecurityScanTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapSecurityScanExtension.class);

    private ZapScannerConfiguration config = new ZapScannerConfiguration();

    private static ZapScanner mockZapScanner;

    @BeforeAll
    static void replaceScannerFactory(){
        mockZapScanner = mock(ZapScanner.class);
        ZapSecurityScanExtension.setZapScannerFactory(config -> mockZapScanner);
    }

    @Test
    void verifyZapSecurityScanExtension() {
        when(mockZapScanner.completeScan(anyString(), anyBoolean(), anyString())).thenReturn(
                Arrays.asList(new Alert("test1", "test2", Alert.Risk.Low, Alert.Confidence.Low),
                        new Alert("test1", "test2", Alert.Risk.Low, Alert.Confidence.High)));
    }

    @AfterEach
    void assertNoAlerts(AlertList alerts) {

        LOGGER.info("Performing security scan using policy '{}'", config.getPolicy());

        List<Alert> tempAlert = alerts.getAlerts();
        ContainsNoHighRiskAlertMatcher noHighRisks = new ContainsNoHighRiskAlertMatcher();
        boolean isNoHighRisk = noHighRisks.matchesSafely(tempAlert);

        assertTrue(isNoHighRisk, "Tested workflow should have no high risk alerts");

        LOGGER.debug("Security scan uncovered following alerts {}", alerts.getAlerts());

    }

    @AfterAll
    static void resetScannerFactory(){
        ZapSecurityScanExtension.setZapScannerFactory(ZapSecurityScanExtension.DEFAULT_FACTORY);
    }


}
