package info.novatec.testit;

import org.zaproxy.clientapi.core.Alert;

import java.util.List;

/**
 * {@link ZapSecurityScanExtension} needs a class AlertList instead of List of Alerts.
 */
@SuppressWarnings("ALL")
class AlertList {

    private List<Alert> alerts;

    AlertList(List<Alert> alerts) {
        this.alerts = alerts;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }
}
