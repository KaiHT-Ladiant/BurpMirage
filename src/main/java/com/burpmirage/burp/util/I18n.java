package com.burpmirage.burp.util;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * UI strings loaded from {@code /i18n/messages.properties} (locale-specific per JAR build).
 */
public final class I18n {
    private static final Properties PROPS = new Properties();

    static {
        try (InputStream in = I18n.class.getResourceAsStream("/i18n/messages.properties")) {
            if (in != null) {
                PROPS.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
        }
    }

    private I18n() {
    }

    public static String get(String key) {
        return PROPS.getProperty(key, key);
    }

    public static String format(String key, Object... args) {
        return String.format(get(key), args);
    }
}
