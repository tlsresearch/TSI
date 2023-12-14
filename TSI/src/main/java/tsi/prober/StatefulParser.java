package tsi.prober;

import de.rub.nds.tlsattacker.core.protocol.message.*;

import static tsi.prober.OutputSymbol.SCORE_FIELD_DELIMITER;

public class StatefulParser extends Parser {

    @Override
    protected String parseServerKeyExchangeMessage(ServerKeyExchangeMessage message) {
        return "";
    }

    @Override
    protected String parseCertificateRequestMessage(CertificateRequestMessage message) {
        return "";
    }

    @Override
    protected String parseServerHelloMessage(ServerHelloMessage message) {
        StringBuilder outputSymbol = new StringBuilder("SERVER_HELLO");
        outputSymbol.append(SCORE_FIELD_DELIMITER);
        if (message.getSelectedCipherSuite() != null && message.getSelectedCipherSuite().getValue() != null) {
            outputSymbol.append(Utils.bytesToHex(message.getSelectedCipherSuite().getValue()));
        } else {
            outputSymbol.append("null");
        }
        return outputSymbol.toString();
    }
}
