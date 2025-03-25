package Obs1d1anc1ph3r.dns;

public class DNSLookUp {

    public static void main(String args[]) {
        if (args.length == 0) {
            System.out.println("\033[0;31mUsage: java DNSLookUp <hostname or IP>\033[0m");
            return;
        }

        LookupService lookupService = new LookupService();
        
        for (String arg : args) {
            if (lookupService.isIPAddress(arg)) {
                lookupService.reverseLookup(arg);
            } else {
                lookupService.forwardLookup(arg);
            }
        }
    }
}