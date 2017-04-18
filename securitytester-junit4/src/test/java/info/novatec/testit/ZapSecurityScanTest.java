package info.novatec.testit;

import info.novatec.testit.security.zap.ZapScanner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.zaproxy.clientapi.core.Alert;

import java.util.Arrays;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit test for security test junit rule.
 */
@RunWith ( MockitoJUnitRunner.class )
public class ZapSecurityScanTest {

    @Rule
    public TestZapSecurityScan cut = new TestZapSecurityScan (
            "http://localhost:8080", "apiKey", "localhost", "8085", "default" );

    @Test
    public void verifyZapSecurityScanRule () {
        when ( cut.getZapScanner ().completeScan ( anyString (), anyBoolean(), anyString () ) ).thenReturn (
                Arrays.asList ( new Alert ( "test1", "test2", Alert.Risk.Low, Alert.Confidence.Low ),
                new Alert ( "test1", "test2", Alert.Risk.Low, Alert.Confidence.High ) ) );
    }

    static class TestZapSecurityScan extends ZapSecurityScan {

        public TestZapSecurityScan ( String site, String apiKey, String targetHost, String proxyPort, String policy ) {
            super ( site, apiKey, targetHost, proxyPort, policy );
        }

        @Override
        protected ZapScanner createZapScanner () {
            return mock ( ZapScanner.class );
        }
    }

}