package tsi.prober;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;

import static tsi.prober.OutputSymbol.*;

public abstract class Parser {

    public String parseRecordLayer(Record record) {
        StringBuilder outputSymbol = new StringBuilder();
        if (record.getProtocolVersion() != null) {
            outputSymbol.append(ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue()));
        } else {
            outputSymbol.append("null");
        }
        return outputSymbol.toString();
    }

    public String parseHandshakeLayer(TlsMessage message) {
        String outputSymbol;
        switch (message.getProtocolMessageType()) {
            case UNKNOWN:
                outputSymbol = SYMBOL_UNKNOWN;
                break;
            case ALERT:
                outputSymbol = parseAlertProtocol((AlertMessage) message);
                break;
            case HANDSHAKE:
                outputSymbol = parseHandshakeProtocol((HandshakeMessage) message);
                break;
            case CHANGE_CIPHER_SPEC:
                outputSymbol = parseChangeCipherSpecProtocol((ChangeCipherSpecMessage) message);
                break;
            case APPLICATION_DATA:
                outputSymbol = parseApplicationProtocol((ApplicationMessage) message);
                break;
            case HEARTBEAT:
                outputSymbol = parseHeartbeatProtocol((HeartbeatMessage) message);
                break;
            default:
                outputSymbol = message.toCompactString();
                break;
        }
        return outputSymbol;
    }

    /* ------------------------------------------------------------------------------------------------------------- */

    protected String parseHandshakeProtocol(HandshakeMessage message) {
        switch (message.getHandshakeMessageType()) {
            case UNKNOWN:
                return SYMBOL_UNKNOWN;
            case SERVER_HELLO:
                return parseServerHelloMessage((ServerHelloMessage) message);
            case CERTIFICATE_REQUEST:
                return parseCertificateRequestMessage((CertificateRequestMessage) message);
            case SERVER_KEY_EXCHANGE:
                return parseServerKeyExchangeMessage((ServerKeyExchangeMessage) message);
            case NEW_SESSION_TICKET:
                return parseNewSessionTicketMessage((NewSessionTicketMessage) message);
            default:
                return message.toCompactString();
        }
    }

    protected String parseChangeCipherSpecProtocol(ChangeCipherSpecMessage message) {
        return "CHANGE_CIPHER_SPEC";
    }

    protected String parseApplicationProtocol(ApplicationMessage message) {
        return "APPLICATION_DATA";
    }

    protected String parseAlertProtocol(AlertMessage message) {
        String outputSymbol;
        AlertLevel level = AlertLevel.getAlertLevel(message.getLevel().getValue());
        AlertDescription description = AlertDescription.getAlertDescription(message.getDescription().getValue());
        outputSymbol = "ALERT_" + level.name() + "_";
        if (description == null) {
            outputSymbol += SYMBOL_UNKNOWN;
        } else {
            outputSymbol += description.name();
        }
        return outputSymbol;
    }

    protected String parseHeartbeatProtocol(HeartbeatMessage message) {
        StringBuilder outputSymbol = new StringBuilder("HEARTBEAT_");

        if (message.getHeartbeatMessageType() != null && message.getHeartbeatMessageType().getValue() != null) {
            outputSymbol.append(HeartbeatMessageType.getHeartbeatMessageType(message.getHeartbeatMessageType().getValue())).append("_");
        } else {
            outputSymbol.append("null").append("_");
        }

        if (message.getPayload() != null && message.getPayload().getValue() != null) {
            outputSymbol.append(Utils.bytesToHex(message.getPayload().getValue()));
        } else {
            outputSymbol.append("null");
        }

        return outputSymbol.toString();
    }

    /* ------------------------------------------------------------------------------------------------------------- */

    protected String parseNewSessionTicketMessage(NewSessionTicketMessage message) {
        StringBuilder outputSymbol = new StringBuilder("NEW_SESSION_TICKET_");
        if (message.getTicketLifetimeHint() != null && message.getTicketLifetimeHint().getValue() != null) {
            outputSymbol.append(message.getTicketLifetimeHint().getValue()).append("_");
        } else {
            outputSymbol.append("null").append("_");
        }

        if (message.getTicketLength() != null && message.getTicketLength().getValue() != null) {
            outputSymbol.append(message.getTicketLength().getValue());
        } else {
            outputSymbol.append("null");
        }

        return outputSymbol.toString();
    }

    protected abstract String parseServerKeyExchangeMessage(ServerKeyExchangeMessage message);

    protected abstract String parseCertificateRequestMessage(CertificateRequestMessage message);

    protected abstract String parseServerHelloMessage(ServerHelloMessage message);
}
