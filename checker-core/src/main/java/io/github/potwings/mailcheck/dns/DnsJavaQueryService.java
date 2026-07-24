package io.github.potwings.mailcheck.dns;

import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class DnsJavaQueryService implements DnsQueryService {

    private final Duration timeout;

    public DnsJavaQueryService(Duration timeout) {
        this.timeout = timeout;
    }

    @Override
    public DnsAnswer query(String name, RecordType type) {
        return doQuery(null, name, type);
    }

    @Override
    public DnsAnswer queryVia(String resolverIp, String name, RecordType type) {
        return doQuery(resolverIp, name, type);
    }

    private DnsAnswer doQuery(String resolverIp, String name, RecordType type) {
        try {
            Name qname = type == RecordType.PTR
                    ? ReverseMap.fromAddress(name)
                    : Name.fromString(name.endsWith(".") ? name : name + ".");
            Lookup lookup = new Lookup(qname, toWireType(type));
            SimpleResolver resolver = resolverIp == null ? new SimpleResolver() : new SimpleResolver(resolverIp);
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
            lookup.setCache(null);
            // Never expand bare names with the local search path — all inputs are FQDNs.
            lookup.setSearchPath(new Name[0]);
            Record[] records = lookup.run();

            return switch (lookup.getResult()) {
                case Lookup.SUCCESSFUL -> new DnsAnswer(DnsRcode.NOERROR, toData(records));
                case Lookup.HOST_NOT_FOUND -> DnsAnswer.of(DnsRcode.NXDOMAIN);
                case Lookup.TYPE_NOT_FOUND -> DnsAnswer.of(DnsRcode.NOERROR);
                case Lookup.TRY_AGAIN -> DnsAnswer.of(DnsRcode.TIMEOUT);
                default -> DnsAnswer.of(DnsRcode.SERVFAIL);
            };
        } catch (TextParseException | UnknownHostException e) {
            return DnsAnswer.of(DnsRcode.ERROR);
        }
    }

    private static int toWireType(RecordType type) {
        return switch (type) {
            case A -> Type.A;
            case AAAA -> Type.AAAA;
            case TXT -> Type.TXT;
            case MX -> Type.MX;
            case NS -> Type.NS;
            case CNAME -> Type.CNAME;
            case PTR -> Type.PTR;
        };
    }

    private static List<DnsRecordData> toData(Record[] records) {
        if (records == null) {
            return List.of();
        }
        List<DnsRecordData> out = new ArrayList<>(records.length);
        for (Record r : records) {
            out.add(new DnsRecordData(rdata(r), r.getTTL()));
        }
        return List.copyOf(out);
    }

    private static String rdata(Record r) {
        if (r instanceof TXTRecord txt) {
            return String.join("", txt.getStrings());
        }
        if (r instanceof MXRecord mx) {
            return mx.getPriority() + " " + mx.getTarget().toString(true);
        }
        if (r instanceof ARecord a) {
            return a.getAddress().getHostAddress();
        }
        if (r instanceof AAAARecord aaaa) {
            return aaaa.getAddress().getHostAddress();
        }
        if (r instanceof CNAMERecord c) {
            return c.getTarget().toString(true);
        }
        if (r instanceof NSRecord ns) {
            return ns.getTarget().toString(true);
        }
        if (r instanceof PTRRecord ptr) {
            return ptr.getTarget().toString(true);
        }
        return r.rdataToString();
    }
}
