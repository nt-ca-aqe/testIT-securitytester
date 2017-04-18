package info.novatec.testit.security.zap;

import org.zaproxy.clientapi.core.Alert;
import java.util.List;

/**
 * The ZAProxy scanner.
 */
@SuppressWarnings("unused")
public interface ZapScanner {

    /**
     * Perform passive and active scanning for given baseUrl, inScopeOnly and scanPolicyName.
     *
     * @param baseUrl           base url to scan
     * @param inScopeOnly       set of URLs you are testing,
     *                          and is defined by the Contexts you have specified.<br>
     *                          By default nothing is in scope.
     * @param scanPolicyName    policy name for scan (may be null for default)
     * @return                  list of alerts occurred
     */
    List<Alert> completeScan ( String baseUrl, boolean inScopeOnly, String scanPolicyName );


    /**
     * Performs standard active scanning for given baseUrl, inScopeOnly and scanPolicyName.
     * <p>
     * Active scanning attempts to find potential vulnerabilities by using known attacks against the selected targets.
     * <p>
     * Active scanning is an attack on those targets. <br>
     * You should NOT use it on web applications that you do not own.
     * <p>
     * It should be noted that active scanning can only find certain types of vulnerabilities. <br>
     * Logical vulnerabilities, such as broken access control, will not be found by any active or
     * automated vulnerability scanning. <br>
     * Manual penetration testing should always be performed in addition to active scanning
     * to find all types of vulnerabilities.
     *
     * @param baseUrl                   base url to scan
     * @param inScopeOnly               set of URLs you are testing,
     *                                  and is defined by the Contexts you have specified.<br>
     *                                  By default nothing is in scope.
     * @param scanPolicyName            policy name for scan (may be null for default)
     * @return                          list of alerts occurred
     */
    List<Alert> activeScan(String baseUrl, boolean inScopeOnly, String scanPolicyName);


    /**
     * Performs and enables all active scanning for given baseUrl, inScopeOnly and scanPolicyName. <br>
     * To perform only standard active scan use
     * {@link #activeScan(String baseUrl, boolean inScopeOnly, String scanPolicyName)}
     *
     * @param baseUrl           base url to scan
     * @param inScopeOnly       set of URLs you are testing,
     *                          and is defined by the Contexts you have specified.<br>
     *                          By default nothing is in scope.
     * @param scanPolicyName    policy name for scan (may be null for default)
     * @return                  list of alerts occurred
     */
    List<Alert> allActiveScan(String baseUrl, boolean inScopeOnly, String scanPolicyName);


    /**
     * ZAP passively scans all of the responses from the web application being tested.
     * Passive scanning does not change the responses in any way and is therefore safe to use.
     * Scanned is performed in a background thread
     * to ensure that it does not slow down the exploration of an application.
     * <p>
     * Passive Scan is set by default. Use this method after {@link #disablePassiveScan()}
     */
    void enablePassiveScan();


    /**
     * Disable passive scan.
     * <p>
     * To enable passive scan use {@link #enablePassiveScan()}
     */
    void disablePassiveScan();


    /**
     * A tool that is used to automatically discover new resources (URLs) on a particular Site.
     * It begins with a list of URLs to visit, called the seeds, which depends on how the Spider is started.
     * The Spider then visits these URLs, it identifies all the hyperlinks in the page and
     * adds them to the list of URLs to visit and the process continues recursively as long as new resources are found.
     *
     * @param baseUrl   base url to scan
     */
    void spider(String baseUrl);
}