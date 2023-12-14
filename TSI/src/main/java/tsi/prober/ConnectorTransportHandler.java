package tsi.prober;

import de.rub.nds.tlsattacker.transport.tcp.ClientTcpNoDelayTransportHandler;

import java.io.*;
import java.net.Socket;


public class ConnectorTransportHandler extends ClientTcpNoDelayTransportHandler {
    public ConnectorTransportHandler(long timeout, String hostname, int port) {
        super(timeout, timeout, hostname, port);
    }

    @Override
    public byte[] fetchData() throws IOException {
        BufferedInputStream inStream = new BufferedInputStream(this.inStream);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        if (isClosed()) {
            return stream.toByteArray();
        }

        long minTimeMillies = System.currentTimeMillis() + timeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (stream.toByteArray().length == 0)) {
            inStream.mark(1);
            int test = inStream.read();
            if (test == -1) {
                // Socket is no longer usable, so close it properly
                closeClientConnection();
                return stream.toByteArray();
            }
            inStream.reset();

            while (inStream.available() != 0) {
                int read = inStream.read();

                if (read == -1) {
                    System.out.println("Closing socket");
                    // Properly close the socket if the end of the stream was reached
                    closeClientConnection();
                    return stream.toByteArray();
                }

                stream.write(read);
            }
        }
        return stream.toByteArray();
    }

    @Override
    public void initialize() throws IOException {
        try {
            socket = new Socket(hostname, dstPort);
            // Set timeout so reads won't block forever
            socket.setSoTimeout((int) timeout);

            // Use BufferedStreams so we can mark and look ahead
            PushbackInputStream pis = new PushbackInputStream(socket.getInputStream());
            BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());

            setStreams(pis, bos);
        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        }
    }
}
