package info.novatec.testit;

import org.zaproxy.clientapi.core.Alert;

import java.util.List;

/**
 * {@link ZapSecurityScanExtension} needs a class AlertList instead of List of Alerts.
 */
public class AlertList {

    private List<Alert> alerts;

    public AlertList(List<Alert> alerts) {
        this.alerts = alerts;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }
}
