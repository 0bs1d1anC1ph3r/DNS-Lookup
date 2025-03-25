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
            case Type.A -> {
                ARecord aRecord = (ARecord) record;
                output = "\033[0;32mA Record:\033[0m " + aRecord.getAddress().toString().replaceAll("\\.$", "");
            }
            case Type.AAAA -> {
                AAAARecord aaaaRecord = (AAAARecord) record;
                output = "\033[0;32mAAAA Record:\033[0m " + aaaaRecord.getAddress().toString().replaceAll("\\.$", "");
            }
            case Type.PTR -> {
                PTRRecord ptrRecord = (PTRRecord) record;
                output = "\033[0;32mPTR Record:\033[0m " + ptrRecord.getTarget().toString().replaceAll("\\.$", "");
            }
            case Type.MX -> {
                MXRecord mxRecord = (MXRecord) record;
                output = "\033[0;32mMX Record:\033[0m " + mxRecord.getTarget().toString().replaceAll("\\.$", "");
            }
            case Type.NS -> {
                NSRecord nsRecord = (NSRecord) record;
                output = "\033[0;32mNS Record:\033[0m " + nsRecord.getTarget().toString().replaceAll("\\.$", "");
            }
            case Type.CNAME -> {
                CNAMERecord cnameRecord = (CNAMERecord) record;
                output = "\033[0;32mCNAME Record:\033[0m " + cnameRecord.getTarget().toString().replaceAll("\\.$", "");
            }
            case Type.SOA -> {
                SOARecord soaRecord = (SOARecord) record;
                output = "\033[0;32mSOA Record:\033[0m " + soaRecord.getName().toString().replaceAll("\\.$", "") + " "
                        + soaRecord.rdataToString();
            }
            case Type.TXT -> {
                TXTRecord txtRecord = (TXTRecord) record;
                output = "\033[0;32mTXT Record:\033[0m " + txtRecord.getStrings();
            }
            case Type.SRV -> {
                SRVRecord srvRecord = (SRVRecord) record;
                output = "\033[0;32mSRV Record:\033[0m " + srvRecord.getPriority() + " "
                        + srvRecord.getWeight() + " "
                        + srvRecord.getPort() + " "
                        + srvRecord.getTarget().toString().replaceAll("\\.$", "");
            }
            case Type.CAA -> {
                CAARecord caaRecord = (CAARecord) record;
                output = "\033[0;32mCAA Record:\033[0m " + caaRecord.getTag() + " "
                        + caaRecord.getFlags() + " "
                        + caaRecord.getValue();
            }
            case Type.HINFO -> {
                HINFORecord hinfoRecord = (HINFORecord) record;
                output = "\033[0;32mHINFO Record:\033[0m " + hinfoRecord.getCPU() + " "
                        + hinfoRecord.getOS();
            }
            case Type.LOC -> {
                LOCRecord locRecord = (LOCRecord) record;
                output = "\033[0;32mLOC Record:\033[0m " + locRecord.toString();
            }
            case Type.NAPTR -> {
                NAPTRRecord naptrRecord = (NAPTRRecord) record;
                output = "\033[0;32mNAPTR Record:\033[0m " + naptrRecord.getFlags() + " "
                        + naptrRecord.getService() + " "
                        + naptrRecord.getRegexp() + " "
                        + naptrRecord.getReplacement().toString().replaceAll("\\.$", "");
            }
            case Type.RRSIG -> {
                RRSIGRecord rrsigRecord = (RRSIGRecord) record;
                output = "\033[0;32mRRSIG Record:\033[0m "
                        + "Type: " + rrsigRecord.getTypeCovered() + ", "
                        + "Signer: " + rrsigRecord.getSigner().toString() + ", "
                        + "Signature: " + Arrays.toString(rrsigRecord.getSignature());
            }
            case Type.DNSKEY -> {
                DNSKEYRecord dnskeyRecord = (DNSKEYRecord) record;
                output = "\033[0;32mDNSKEY Record:\033[0m "
                        + "Algorithm: " + dnskeyRecord.getAlgorithm() + ", "
                        + "Public Key: " + Arrays.toString(dnskeyRecord.getKey());
            }
            default -> {
                output = "\033[0;33mUnknown record type: " + record.getType() + "\033[0m";
            }
        }
        System.out.println(output);
    }
}