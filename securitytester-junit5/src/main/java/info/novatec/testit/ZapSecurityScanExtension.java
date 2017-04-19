package info.novatec.testit;

import info.novatec.testit.security.zap.ZapScanner;
import info.novatec.testit.security.zap.ZapScannerImpl;

import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.api.extension.TestExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.Alert;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;


public class ZapSecurityScanExtension implements BeforeEachCallback, AfterTestExecutionCallback, ParameterResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapSecurityScanExtension.class);

    static final Function<ZapScannerConfiguration, ZapScanner>  DEFAULT_FACTORY =(config) -> new ZapScannerImpl(config.getApiKey(),config.getTargetHost(), config.getProxyPort());

    private static Function<ZapScannerConfiguration, ZapScanner> zapScannerFactory = DEFAULT_FACTORY;

    static void setZapScannerFactory(Function<ZapScannerConfiguration, ZapScanner> factory){
        zapScannerFactory = factory;
    }


    @Override
    public void beforeEach(TestExtensionContext context) {
        @SuppressWarnings("OptionalGetWithoutIsPresent")
        Field[] declaredFields = context.getTestClass().get().getDeclaredFields();

        List<Field> configFields = Arrays.stream(declaredFields).filter(field -> field.getType()
                .equals(ZapScannerConfiguration.class)).collect(Collectors.toList());

        if(configFields.size() != 1){
            throw new IllegalStateException("There is no unique ConfigFields");
        }

        Field field = configFields.get(0);
        field.setAccessible(true);
        ZapScannerConfiguration config = null;
        try {
            config = (ZapScannerConfiguration) field.get(context.getTestInstance());
        } catch (IllegalAccessException e) {
            LOGGER.error("Illegal Access Exception in beforeEach method: " + e.getMessage());
        }

        LOGGER.info("Initializing zap scanner");
        ZapScanner zapScanner = zapScannerFactory.apply(config);

        ExtensionContext.Namespace namespace = ExtensionContext.Namespace.create("zap.scanner");
        ExtensionContext.Store store = context.getStore(namespace);
        store.put("zapScanner", zapScanner);
        store.put("zapScannerConfiguration", config);
    }

    @Override
    public void afterTestExecution(TestExtensionContext context) {
        ExtensionContext.Namespace namespace = ExtensionContext.Namespace.create("zap.scanner");
        ExtensionContext.Store store = context.getStore(namespace);

        ZapScannerConfiguration config = store.get("zapScannerConfiguration", ZapScannerConfiguration.class);
        ZapScanner zapScanner = store.get("zapScanner", ZapScanner.class);

        List<Alert> listOfAlerts = zapScanner.completeScan(config.getBaseUrl(), config.isInScopeOnly(), config.getPolicy());
        AlertList alerts = new AlertList(listOfAlerts);
        store.put("alerts", alerts);
    }

    @Override
    public boolean supports(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return parameterContext.getParameter().getType().equals(AlertList.class);
    }

    @Override
    public Object resolve(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        ExtensionContext.Namespace namespace = ExtensionContext.Namespace.create("zap.scanner");
        ExtensionContext.Store store = extensionContext.getStore(namespace);
        return store.get("alerts", AlertList.class);
    }
}