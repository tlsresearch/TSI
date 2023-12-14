package tsi.prober;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static tsi.prober.OutputSymbol.SCORE_FIELD_DELIMITER;

public class StatelessParser extends Parser {

    @Override
    protected String parseServerKeyExchangeMessage(ServerKeyExchangeMessage message) {
        StringBuilder res = new StringBuilder("ECDHEServerKeyExchange:");
        if (message.getLength() != null && message.getLength().getValue() != null) {
            res.append(message.getLength().getValue());
        } else {
            res.append("null");
        }
        return res.toString();
    }

    @Override
    protected String parseCertificateRequestMessage(CertificateRequestMessage message) {
        StringBuilder outputSymbol = new StringBuilder("CertificateRequest:");
        if (message.getSignatureHashAlgorithms() != null &&
                message.getSignatureHashAlgorithms().getValue() != null) {
            try {
                List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                        message.getSignatureHashAlgorithms().getValue()
                );
                List<String> algoAndHashString = new ArrayList<>();
                for (SignatureAndHashAlgorithm algo : signatureAndHashAlgorithms) {
                    algoAndHashString.add(Utils.bytesToHex(algo.getByteValue()));
                }
                algoAndHashString.sort(Comparator.naturalOrder());
                for (String algo : algoAndHashString) {
                    outputSymbol.append(algo).append("_");
                }
            } catch (Exception var5) {
                System.out.println("Error: Parse SignatureAndHashAlgorithms in CertificateRequest.");
            }
        } else {
            outputSymbol.append("null").append("_");
        }
        return outputSymbol.substring(0, outputSymbol.length() - 1);
    }

    @Override
    protected String parseServerHelloMessage(ServerHelloMessage message) {
        StringBuilder outputSymbol = new StringBuilder();

        outputSymbol.append("Version:");
        if (message.getProtocolVersion() != null) {
            outputSymbol.append(ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue()));
        } else {
            outputSymbol.append("null");
        }

        outputSymbol.append(SCORE_FIELD_DELIMITER + "CipherSuite:");
        if (message.getSelectedCipherSuite() != null && message.getSelectedCipherSuite().getValue() != null) {
            outputSymbol.append(Utils.bytesToHex(message.getSelectedCipherSuite().getValue()));
        } else {
            outputSymbol.append("null");
        }


        String renegotiation = SCORE_FIELD_DELIMITER + "Renegotiation:null";
        String heartbeat = SCORE_FIELD_DELIMITER + "Heartbeat:False";
        String ECPointFormats = SCORE_FIELD_DELIMITER + "ECPointFormats:";
        if (message.getExtensions() != null) {
            for (ExtensionMessage e : message.getExtensions()) {
                // if it's some special Extension (such as Heartbeat), append the content of it, else append the length
                if (ExtensionType.getExtensionType(e.getExtensionType().getValue()) == ExtensionType.HEARTBEAT) {
                    heartbeat = SCORE_FIELD_DELIMITER + "Heartbeat:True";
                } else if (ExtensionType.getExtensionType(e.getExtensionType().getValue()) == ExtensionType.RENEGOTIATION_INFO) {
                    renegotiation = SCORE_FIELD_DELIMITER + "Renegotiation:" + Utils.bytesToHex(e.getExtensionType().getValue())
                            + "_" + e.getExtensionLength().getValue();
                } else if (ExtensionType.getExtensionType(e.getExtensionType().getValue()) == ExtensionType.EC_POINT_FORMATS) {
                    ECPointFormats = SCORE_FIELD_DELIMITER + "ECPointFormats:" + Utils.bytesToHex(e.getExtensionType().getValue())
                            + "_" + Utils.bytesToHex(e.getExtensionBytes().getValue());
                }
            }
        }
        outputSymbol.append(renegotiation);
        outputSymbol.append(heartbeat);
        outputSymbol.append(ECPointFormats);

        return outputSymbol.toString();
    }
}
