package tsi.prober.probe;

import tsi.prober.Connector;
import tsi.prober.Parser;

import java.util.*;

import static tsi.prober.InputSymbol.*;
import static tsi.prober.OutputSymbol.*;

public class StatefulProbe extends Probe {

    public StatefulProbe(String[] requests, Parser parser, String ID) {
        this.requests = requests;
        this.parser = parser;
        this.ID = ID;
    }

    @Override
    public List<String> probe(Connector connector, boolean isEmptyCertAcceptable) {
        List<String> responses = new ArrayList<>();
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

            String response;
            try {
                if (request.contains(CKE)) {
                    if (request.contains("bad")) {
                        if (CKE_Suffix.equals("ECDH")) {
                            request = CKE_RSA;
                        } else {
                            request = CKE_ECDH;
                        }
                    } else {
                        request = CKE + CKE_Suffix;
                    }
                }
                response = connector.processInput(request, parser);
                if (response.contains("|")) {
                    response = response.split("\\|" , 2)[1];
                }

                if (response.contains("SERVER_HELLO")) {
                    String[] messages = response.split("\\|");
                    String[] serverHello = messages[0].split("\\$");
                    switch (serverHello[1]) {
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
                    List<String> receivedMessages = new LinkedList<>();
                    receivedMessages.add(serverHello[0]);
                    receivedMessages.addAll(List.of(Arrays.copyOfRange(messages, 1, messages.length)));
                    response = String.join("|", receivedMessages);
                }
                responses.add(response);

                if (response.contains(SYMBOL_CONNECTION_CLOSED))
                    break;
            } catch (Exception e) {
                System.err.printf("A error happened when send requests, probe ID: %s%n", ID);
                System.exit(1);
            }
        }

        return responses;
    }


}
