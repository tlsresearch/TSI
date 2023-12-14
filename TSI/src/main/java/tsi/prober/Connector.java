package tsi.prober;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.*;

import static tsi.prober.OutputSymbol.*;

public class Connector {


    Config tlsAttackerConfig;
    State tlsAttackerState;
    String tlsAttackerMessageDir;
    HashMap<String, WorkflowTrace> tlsAttackerMessages = new HashMap<>();

    String targetHostname;
    int targetPort;
    int timeout;
    List<String> cipherSuiteStrings;
    String protocolVersionString;
    String compressionMethodString;

    public Connector(
            String targetHostname,
            int targetPort,
            int timeout,
            List<String> cipherSuiteStrings,
            String protocolVersionString,
            String compressionMethodString,
            String tlsAttackerMessageDir
    ) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.OFF);

        this.targetHostname = targetHostname;
        this.targetPort = targetPort;
        this.timeout = timeout;
        this.cipherSuiteStrings = cipherSuiteStrings;
        this.protocolVersionString = protocolVersionString;
        this.compressionMethodString = compressionMethodString;
        this.tlsAttackerMessageDir = tlsAttackerMessageDir;

        initialiseTlsAttacker();
    }

    private void initialiseTlsAttacker() throws Exception {
        tlsAttackerConfig = Config.createConfig();
        tlsAttackerConfig.setEnforceSettings(false);

        loadMessages(tlsAttackerMessageDir);

        OutboundConnection clientConnection = new OutboundConnection(targetPort, targetHostname);
        clientConnection.setTimeout(timeout);
        tlsAttackerConfig.setDefaultClientConnection(clientConnection);

        List<CipherSuite> cipherSuites = new LinkedList<>();
        for (String cipherSuiteString : cipherSuiteStrings) {
            try {
                cipherSuites.add(CipherSuite.valueOf(cipherSuiteString));
            } catch (IllegalArgumentException e) {
                throw new Exception("Unknown CipherSuite " + cipherSuiteString);
            }
        }
        if (cipherSuites.isEmpty()) {
            cipherSuites = Arrays.asList(CipherSuite.values());
        }

        CompressionMethod compressionMethod;
        try {
            compressionMethod = CompressionMethod.valueOf(compressionMethodString);
        } catch (IllegalArgumentException e) {
            throw new Exception("Unknown CompressionMethod " + compressionMethodString);
        }

        ProtocolVersion protocolVersion = ProtocolVersion.fromString(protocolVersionString);
        tlsAttackerConfig.setHighestProtocolVersion(protocolVersion);
        tlsAttackerConfig.setDefaultSelectedProtocolVersion(protocolVersion);
        tlsAttackerConfig.setDefaultHighestClientProtocolVersion(protocolVersion);

        tlsAttackerConfig.setDefaultSelectedCipherSuite(cipherSuites.get(0));
        tlsAttackerConfig.setDefaultClientSupportedCipherSuites(cipherSuites);

        List<CompressionMethod> compressionMethods = new LinkedList<>();
        compressionMethods.add(compressionMethod);
//        compressionMethods.add(CompressionMethod.valueOf("DEFLATE"));
        tlsAttackerConfig.setDefaultClientSupportedCompressionMethods(compressionMethods);

        tlsAttackerConfig.setDefaultClientDhGenerator(new BigInteger("2"));
        tlsAttackerConfig.setDefaultClientDhModulus(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
        tlsAttackerConfig.setDefaultClientDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
        tlsAttackerConfig.setDefaultClientDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
        tlsAttackerConfig.setDefaultServerDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
        tlsAttackerConfig.setDefaultServerDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));

//        tlsAttackerConfig.setAddRenegotiationInfoExtension(true);
//        tlsAttackerConfig.setAddHeartbeatExtension(true);
//        tlsAttackerConfig.setAddECPointFormatExtension(true);
//        tlsAttackerConfig.setAddEllipticCurveExtension(true);
//        tlsAttackerConfig.setAddSessionTicketTLSExtension(true);
//        tlsAttackerConfig.setAddSignatureAndHashAlgorithmsExtension(true);

        initialiseSession();
    }

    private void initialiseSession() {
        tlsAttackerState = new State(tlsAttackerConfig);

        TlsContext context = tlsAttackerState.getTlsContext();

//        TransportHandler transportHandler = TransportHandlerFactory.createTransportHandler(tlsAttackerConfig.getConnectionEnd());
        ConnectorTransportHandler transportHandler = new ConnectorTransportHandler(tlsAttackerConfig.getDefaultClientConnection().getTimeout(), tlsAttackerConfig.getDefaultClientConnection().getHostname(), tlsAttackerConfig.getDefaultClientConnection().getPort());
        context.setTransportHandler(transportHandler);

        context.initTransportHandler();
        context.initRecordLayer();
    }

    private void loadMessages(String dirPath) throws Exception {
        File dir = new File(dirPath);

        if (!dir.isDirectory()) {
            throw new Exception(dirPath + " is not a valid directory");
        }

        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.toLowerCase().endsWith(".xml");
            }
        });

        assert files != null;

        for (File file : files) {
            String name = file.getName().substring(0, file.getName().length() - 4);

            FileInputStream input = new FileInputStream(file.getAbsolutePath());
            WorkflowTrace trace = WorkflowTraceSerializer.secureRead(input);

            tlsAttackerMessages.put(name, trace);
        }
    }

    /* ------------------------------------------------------------------------------------------------------------- */
    public void reset() throws Exception {
        closeConnection();
        initialiseSession();
//        initialiseTlsAttacker();
    }

    private void closeConnection() throws IOException {
        tlsAttackerState.getTlsContext().getTransportHandler().closeConnection();
    }

    /* ------------------------------------------------------------------------------------------------------------- */

    public String processInput(String inputSymbol, Parser parser) throws Exception {
        if (tlsAttackerState.getTlsContext().getTransportHandler().isClosed()) {
            return SYMBOL_CONNECTION_CLOSED;
        }

        // Process the regular input symbols
        if (tlsAttackerMessages.containsKey(inputSymbol)) {
            sendMessage(tlsAttackerMessages.get(inputSymbol));
        } else {
            throw new Exception("Unknown input symbol: " + inputSymbol);
        }

        return receiveMessages(parser);
    }

    private void sendMessage(WorkflowTrace trace) throws Exception {
        for (TlsAction tlsAction : trace.getTlsActions()) {
            try {
                tlsAction.normalize();
                tlsAction.execute(tlsAttackerState);
            } catch (WorkflowExecutionException e) {
                // TODO Auto-generated catch block
                throw new Exception("TLSAttacker send message failed.");
            }
        }
        trace.reset();
    }

    protected String receiveMessages(Parser parser) throws IOException {
        if (tlsAttackerState.getTlsContext().getTransportHandler().isClosed()) {
            return SYMBOL_CONNECTION_CLOSED;
        }

        List<String> receivedMessages = new LinkedList<>();
        ReceiveAction action = new ReceiveAction(new LinkedList<ProtocolMessage>());
        // Need to normalize otherwise an exception is thrown about no connection existing with alias 'null'
        action.normalize();
        // Perform the actual receiving of the message
        action.execute(tlsAttackerState);

        String outputMessage;

        // Check for every record if the MAC is valid. If it is not, do not
        // continue reading it since its contents might be illegible.
        for (AbstractRecord abstractRecord : action.getReceivedRecords()) {
            if (BlobRecord.class.isAssignableFrom(abstractRecord.getClass())) {
                receivedMessages.add("blobRecord");
                continue;
            }
            Record record = (Record) abstractRecord;
            outputMessage = parser.parseRecordLayer(record);
            if (!Objects.equals(outputMessage, "")) {
                receivedMessages.add(outputMessage);
            }
            if (record.getComputations() == null) {
                continue;
            }
            if (record.getComputations().getMacValid() == null) {
                continue;
            }
            if (!record.getComputations().getMacValid()) {
                if (tlsAttackerState.getTlsContext().getTransportHandler().isClosed()) {
                    return "InvalidMAC" + SYMBOL_JOINER + SYMBOL_CONNECTION_CLOSED;
                } else {
                    return "InvalidMAC";
                }
            }
        }
        if (!receivedMessages.isEmpty()) {
            outputMessage = String.join(SCORE_FIELD_DELIMITER, receivedMessages);
            receivedMessages.clear();
            receivedMessages.add(outputMessage);
        }


        // Iterate over all received messages and build a string containing their respective types
        for (ProtocolMessage message : action.getReceivedMessages()) {
            outputMessage = parser.parseHandshakeLayer((TlsMessage) message);
            if (!Objects.equals(outputMessage, "")) {
                receivedMessages.add(outputMessage);
            }
        }

        if (tlsAttackerState.getTlsContext().getTransportHandler().isClosed()) {
            receivedMessages.add(SYMBOL_CONNECTION_CLOSED);
        }

        if (!receivedMessages.isEmpty()) {
            return String.join(SYMBOL_JOINER, receivedMessages);
        } else {
            return SYMBOL_NO_RESPONSE;
        }
    }

    /* ------------------------------------------------------------------------------------------------------------- */

    public String getTargetHostname() {
        return targetHostname;
    }

    public int getTargetPort() {
        return targetPort;
    }
}
