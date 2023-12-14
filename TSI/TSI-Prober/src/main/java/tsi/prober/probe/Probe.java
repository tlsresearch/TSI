package tsi.prober.probe;

import tsi.prober.Connector;
import tsi.prober.Parser;

import java.util.List;

public abstract class Probe {
    public String ID;
    String[] requests;
    Parser parser;
    public abstract List<String> probe(Connector connector, boolean isCertificateMandatory);

    public String getID() {
        return ID;
    }

    public String[] getRequests() {
        return requests;
    }
}
