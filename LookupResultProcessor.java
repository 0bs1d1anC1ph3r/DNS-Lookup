package Obs1d1anc1ph3r.dns;

import java.util.Arrays;
import org.xbill.DNS.*;

public class LookupResultProcessor {

    public static void resolveRecords(Lookup lookup) {
        lookup.run();
        if (lookup.getResult() == Lookup.SUCCESSFUL) {
            if (lookup.getAnswers() != null && lookup.getAnswers().length > 0) {
                for (org.xbill.DNS.Record record : lookup.getAnswers()) {
                    processRecord(record);
                }
            } else {
                System.out.println("\033[0;33mNo records found for this query (" + Arrays.toString(lookup.getAliases()) + ").\033[0m");
            }
        } else {
            String resultMessage = getResultMessage(lookup);
            System.out.println("\033[0;31mLookup failed for " + Arrays.toString(lookup.getAliases()) + ": " + resultMessage + "\033[0m");
        }
    }

    public static String getResultMessage(Lookup lookup) {
        int resultCode = lookup.getResult();

        if (resultCode == Lookup.HOST_NOT_FOUND) {
            return "Host not found (Code: " + resultCode + ")";
        } else if (resultCode == Lookup.TYPE_NOT_FOUND) {
            return "Record type not found (Code: " + resultCode + ")";
        } else if (resultCode == Rcode.SERVFAIL) {
            return "Temporary error (Code: " + resultCode + ")";
        } else if (resultCode == Rcode.NXDOMAIN) {
            return "Permanent error (Code: " + resultCode + ")";
        } else {
            return "Unknown error (Code: " + resultCode + ")";
        }
    }

    public static void resolveRecord(Lookup lookup, Resolver resolver) {
        try {
            lookup.setResolver(resolver);
            lookup.run();

            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                if (lookup.getAnswers() != null && lookup.getAnswers().length > 0) {
                    for (org.xbill.DNS.Record record : lookup.getAnswers()) {
                        processRecord(record);
                    }
                } else {
                    System.out.println("\033[0;33mNo records found for this query (" + Arrays.toString(lookup.getAliases()) + ").\033[0m");
                }
            } else {
                String resultMessage = getResultMessage(lookup);
                System.out.println("\033[0;31mLookup failed for " + Arrays.toString(lookup.getAliases()) + ": " + resultMessage + "\033[0m");
            }
        } catch (Exception e) {
            System.out.println("\033[0;31mAn unexpected error occurred while resolving " + Arrays.toString(lookup.getAliases()) + ": " + e.getMessage() + "\033[0m");
            LoggerUtility.logError("Error resolving " + Arrays.toString(lookup.getAliases()), e);
        }
    }

    public static void processRecord(org.xbill.DNS.Record record) {
        String output;
        switch (record.getType()) {
            case Type.A ->
                output = formatARecord((ARecord) record);
            case Type.AAAA ->
                output = formatAAAARecord((AAAARecord) record);
            case Type.PTR ->
                output = formatPTRRecord((PTRRecord) record);
            case Type.MX ->
                output = formatMXRecord((MXRecord) record);
            case Type.NS ->
                output = formatNSRecord((NSRecord) record);
            case Type.CNAME ->
                output = formatCNAMERecord((CNAMERecord) record);
            case Type.SOA ->
                output = formatSOARecord((SOARecord) record);
            case Type.TXT ->
                output = formatTXTRecord((TXTRecord) record);
            case Type.SRV ->
                output = formatSRVRecord((SRVRecord) record);
            case Type.CAA ->
                output = formatCAARecord((CAARecord) record);
            case Type.HINFO ->
                output = formatHINFORecord((HINFORecord) record);
            case Type.LOC ->
                output = formatLOCRecord((LOCRecord) record);
            case Type.NAPTR ->
                output = formatNAPTRRecord((NAPTRRecord) record);
            case Type.RRSIG ->
                output = formatRRSIGRecord((RRSIGRecord) record);
            case Type.DNSKEY ->
                output = formatDNSKEYRecord((DNSKEYRecord) record);
            case Type.NSEC ->
                output = formatNSECRecord((NSECRecord) record);
            case Type.NSEC3 ->
                output = formatNSEC3Record((NSEC3Record) record);
            case Type.TLSA ->
                output = formatTLSARecord((TLSARecord) record);
            default ->
                output = "\033[0;33mUnknown record type: " + record.getType() + "\033[0m";
        }
        System.out.println(output);
    }

    private static String formatARecord(ARecord record) {
        return "\033[0;32mA Record:\033[0m " + record.getAddress().toString().replaceAll("\\.$", "");
    }

    private static String formatAAAARecord(AAAARecord record) {
        return "\033[0;32mAAAA Record:\033[0m " + record.getAddress().toString().replaceAll("\\.$", "");
    }

    private static String formatPTRRecord(PTRRecord record) {
        return "\033[0;32mPTR Record:\033[0m " + record.getTarget().toString().replaceAll("\\.$", "");
    }

    private static String formatMXRecord(MXRecord record) {
        return "\033[0;32mMX Record:\033[0m " + record.getTarget().toString().replaceAll("\\.$", "");
    }

    private static String formatNSRecord(NSRecord record) {
        return "\033[0;32mNS Record:\033[0m " + record.getTarget().toString().replaceAll("\\.$", "");
    }

    private static String formatCNAMERecord(CNAMERecord record) {
        return "\033[0;32mCNAME Record:\033[0m " + record.getTarget().toString().replaceAll("\\.$", "");
    }

    private static String formatSOARecord(SOARecord record) {
        return "\033[0;32mSOA Record:\033[0m " + record.getName().toString().replaceAll("\\.$", "") + " " + record.rdataToString();
    }

    private static String formatTXTRecord(TXTRecord record) {
        return "\033[0;32mTXT Record:\033[0m " + record.getStrings();
    }

    private static String formatSRVRecord(SRVRecord record) {
        return "\033[0;32mSRV Record:\033[0m " + record.getPriority() + " " + record.getWeight() + " " + record.getPort() + " " + record.getTarget().toString().replaceAll("\\.$", "");
    }

    private static String formatCAARecord(CAARecord record) {
        return "\033[0;32mCAA Record:\033[0m " + record.getTag() + " " + record.getFlags() + " " + record.getValue();
    }

    private static String formatHINFORecord(HINFORecord record) {
        return "\033[0;32mHINFO Record:\033[0m " + record.getCPU() + " " + record.getOS();
    }

    private static String formatLOCRecord(LOCRecord record) {
        return "\033[0;32mLOC Record:\033[0m " + record.toString();
    }

    private static String formatNAPTRRecord(NAPTRRecord record) {
        return "\033[0;32mNAPTR Record:\033[0m " + record.getFlags() + " " + record.getService() + " " + record.getRegexp() + " " + record.getReplacement().toString().replaceAll("\\.$", "");
    }

    private static String formatRRSIGRecord(RRSIGRecord record) {
        return "\033[0;32mRRSIG Record:\033[0m " + "Type: " + record.getTypeCovered() + ", " + "Signer: " + record.getSigner().toString() + ", " + "Signature: " + Arrays.toString(record.getSignature());
    }

    private static String formatDNSKEYRecord(DNSKEYRecord record) {
        return "\033[0;32mDNSKEY Record:\033[0m " + "Algorithm: " + record.getAlgorithm() + ", " + "Public Key: " + Arrays.toString(record.getKey());
    }

    private static String formatNSECRecord(NSECRecord record) {
        return "\033[0;32mNSEC Record:\033[0m " + record.toString();
    }

    private static String formatNSEC3Record(NSEC3Record record) {
        return "\033[0;32mNSEC3 Record:\033[0m " + record.toString();
    }

    private static String formatTLSARecord(TLSARecord record) {
        return "\033[0;32mTLSA Record:\033[0m " + record.toString();
    }
}
