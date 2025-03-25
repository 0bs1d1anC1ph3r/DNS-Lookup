package Obs1d1anc1ph3r.dns;

import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.xbill.DNS.*;

public class LookupService {

    private static final int TIMEOUT = 5;

    public boolean isIPAddress(String input) {
        return input.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
    }

    public void reverseLookup(String ipAddress) {
        try {
            String reverseIP = ReverseMap.fromAddress(ipAddress).toString();
            reverseIP = reverseIP.endsWith(".") ? reverseIP.substring(0, reverseIP.length() - 1) : reverseIP;
            Lookup reverseLookup = new Lookup(reverseIP, Type.PTR);
            LookupResultProcessor.resolveRecords(reverseLookup);

            if (reverseLookup.getResult() == Lookup.SUCCESSFUL) {
                for (org.xbill.DNS.Record record : reverseLookup.getAnswers()) {
                    if (record instanceof PTRRecord ptrRecord) {
                        String domain = ptrRecord.getTarget().toString().replaceAll("\\.$", "");
                        System.out.println("\033[0;34mPTR Record (Hostname):\033[0m " + domain);
                        runLookup(domain, new int[]{Type.AAAA, Type.A});
                    }
                }
            }
        } catch (TextParseException e) {
            System.out.println("\033[0;31mInvalid IP address for reverse lookup: " + ipAddress + "\033[0m");
        } catch (UnknownHostException ex) {
            LoggerUtility.logError("Error in reverse lookup for IP: " + ipAddress, ex);
        }
    }

    public void forwardLookup(String domain) {
        runLookup(domain, new int[]{
                Type.A, Type.AAAA, Type.MX, Type.NS, Type.CNAME, Type.SOA,
                Type.TXT, Type.SRV, Type.CAA, Type.HINFO, Type.LOC, Type.NAPTR,
                Type.DNSKEY, Type.RRSIG
        });
    }

    private void runLookup(String domain, int[] recordTypes) {
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        try {
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(TIMEOUT * 1000);

            for (int type : recordTypes) {
                executorService.submit(() -> {
                    try {
                        Lookup lookup = new Lookup(Name.fromString(domain), type);
                        LookupResultProcessor.resolveRecord(lookup, resolver);
                    } catch (TextParseException ex) {
                        LoggerUtility.logError("Error resolving record for " + domain + " (Type: " + type + ")", ex);
                    }
                });
            }
        } catch (UnknownHostException ex) {
            LoggerUtility.logError("Unknown host: " + domain, ex);
        } finally {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(TIMEOUT, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException ex) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}