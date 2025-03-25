package Obs1d1anc1ph3r.dns;

import java.util.logging.Level;
import java.util.logging.Logger;

public class LoggerUtility {

    private static final Logger LOGGER = Logger.getLogger(LoggerUtility.class.getName());

    public static void logError(String message, Exception ex) {
        LOGGER.log(Level.SEVERE, message, ex);
    }
}