import info.novatec.testit.security.zap.ZapScanner;
import info.novatec.testit.security.zap.ZapScannerImpl;

/**
 * Test for scanning with ZapScanner
 */
public class ZapScannerTest {

    public static void main(String[] args){

        String baseUrl = "http://localhost:8080/bodgeit/";
        String apiKey = "afe"; //get the latest apiKey from: ZAP->Tools->Options->API->API-Key->Copy and paste it here!
        String host = "Localhost";
        String zapPort = "8090";

        ZapScanner zapScanner = new ZapScannerImpl(apiKey, host, zapPort, true);

        zapScanner.completeScan(baseUrl, false, "");

    }
}
