package tsi.prober.probe;

import tsi.prober.Connector;
import tsi.prober.Parser;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static tsi.prober.InputSymbol.*;
import static tsi.prober.OutputSymbol.*;

public class StatelessProbe extends Probe{

    public StatelessProbe(Parser parser) {
        requests = new String[]{CH, CERT, CKE, CCS, FIN, CH};
        this.parser = parser;
        this.ID = "CH,CERT,CKE,CCS,FIN,CH";
    }

    @Override
    public List<String> probe(Connector connector, boolean isEmptyCertAcceptable) {
        List<String> result = new ArrayList<>();
        String CKE_Suffix = "ECDH";

        try {
            connector.reset();
        } catch (Exception e) {
            System.err.printf("A error happened when reset connector, probe ID: %s%n", ID);
            System.exit(1);
        }

        for (String request : requests) {
            if (!isEmptyCertAcceptable && Objects.equals(request, CERT)) {
                continue;
            }
            if (request.contains(CKE)) {
                if (request.contains("bad"))
                    if (CKE_Suffix.equals("ECDH")) {
                        request = CKE_RSA;
                    } else {
                        request = CKE_ECDH;
                    }
                else
                    request = CKE + CKE_Suffix;
            }
            try {
                String response = connector.processInput(request, parser);
                if (request.equals(CH)) {
                    ArrayList<String> responses = new ArrayList<>();
                    if (response.contains("|")) {
                        String record = response.split("\\|", 2)[0];
                        String handshake = response.split("\\|", 2)[1];
                        if (handshake.contains("CipherSuite:")) {
                            String[] serverHello = handshake.split("\\|")[0].split("\\$");
                            responses.add("Record:" + record);
                            responses.add("RecordSize:" + record.split("\\$").length);
                            responses.addAll(List.of(serverHello));
                            switch (serverHello[1].replace("CipherSuite:", "")) {
                                case "C02F":
                                    CKE_Suffix = "ECDH";
                                    break;
                                case "002F":
                                case "000A":
                                    CKE_Suffix = "RSA";
                                    break;
                                case "0039":
                                case "0033":
                                case "0016":
                                    CKE_Suffix = "DH";
                                    break;
                                case "null":
                                    System.err.println("Error: CipherSuite is null!");
                                    System.exit(1);
                                    break;
                                default:
                                    System.err.printf("Error: Unknown CipherSuite: %s%n", serverHello[1]);
                                    System.exit(1);
                            }
                            for (String message : handshake.split("\\|")) {
                                if (message.contains("ECDHEServerKeyExchange") || message.contains("CertificateRequest")) {
                                    responses.add(message);
                                }
                            }
                        } else {
                            responses.add(response.split("\\|", 2)[1]);
                        }
                    } else {
                        responses.add(response);
                    }

                    result.addAll(responses);
                    result.add("");
                }
            } catch (Exception e) {
                System.err.printf("A error happened when send requests, probe ID: %s%n", ID);
                System.exit(1);
            }
        }
        return result;
    }
}
