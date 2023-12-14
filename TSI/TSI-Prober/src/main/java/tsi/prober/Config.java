package tsi.prober;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
    Properties properties;
    /** CVE Neo4j Database Configs **/
    String database;
    String username;
    String password;
    String tls_implementations;
    /** Prober Configs **/
    String output_dir;
    String output_filename;
    int interval;
    /** TLS-Attacker Configs **/
    String hostname;
    int port;
    int timeout;
    String cipher_suites;
    String version;
    String compression_method;
    String message_dir;


    public Config(String filename) throws IOException {
        properties = new Properties();
        InputStream input = new FileInputStream(filename);
        properties.load(input);
        loadProperties();
    }

    private void loadProperties() {
        if(properties.getProperty("database") != null)
            database = properties.getProperty("database");
        else
            database = "bolt://localhost:7687";

        if(properties.getProperty("interval") != null)
            interval = Integer.parseInt(properties.getProperty("interval"));
        else
            interval = 60000;

        if(properties.getProperty("username") != null)
            username = properties.getProperty("username");
        else
            username = "username";

        if(properties.getProperty("password") != null)
            password = properties.getProperty("password");
        else
            password = "password";

        if(properties.getProperty("tls_implementations") != null)
            tls_implementations = properties.getProperty("tls_implementations");
        else
            tls_implementations = "";

        // TLS-Attacker parameters
        if(properties.getProperty("hostname") != null)
            hostname = properties.getProperty("hostname");
        else
            hostname = "localhost";

        if(properties.getProperty("port") != null)
            port = Integer.parseInt(properties.getProperty("port"));
        else
            port = 443;

        if(properties.getProperty("timeout") != null)
            timeout = Integer.parseInt(properties.getProperty("timeout"));
        else
            timeout = 1000;

        if(properties.getProperty("cipher_suites") != null)
            cipher_suites = properties.getProperty("cipher_suites");
        else
            cipher_suites = "TLS_RSA_WITH_AES_128_CBC_SHA";

        if(properties.getProperty("version") != null)
            version = properties.getProperty("version");
        else
            version = "TLS12";

        if(properties.getProperty("compression_method") != null)
            compression_method = properties.getProperty("compression_method");
        else
            compression_method = "NULL";

        if(properties.getProperty("message_dir") != null)
            message_dir = properties.getProperty("message_dir");
        else
            message_dir = "./input/TLSAttackerMessages";

        if(properties.getProperty("output_dir") != null)
            output_dir = properties.getProperty("output_dir");
        else
            output_dir = "output";

        if(properties.getProperty("output_filename") != null)
            output_filename = properties.getProperty("output_filename");
        else
            output_filename = hostname;
    }

    protected String getDatabase() {
        return database;
    }

    protected void setDatabase(String database) {
        this.database = database;
    }

    protected String getOutputDir() {
        return output_dir;
    }

    protected void setOutputDir(String output_dir) {
        this.output_dir = output_dir;
    }

    protected String getOutputFilename() {
        return output_filename;
    }

    protected void setOutputFilename(String output_filename) {
        this.output_filename = output_filename;
    }

    protected void setInterval(int interval) {
        this.interval = interval;
    }

    protected int getInterval() {
        return interval;
    }

    protected String getUsername() {
        return username;
    }

    protected void setUsername(String username) {
        this.username = username;
    }

    protected String getPassword() {
        return password;
    }

    protected void setPassword(String password) {
        this.password = password;
    }

    protected String getTlsLib() {
        return tls_implementations;
    }

    protected void setTlsLib(String tlsLib) {
        this.tls_implementations = tlsLib;
    }

    protected String getHostname() {
        return hostname;
    }

    protected void setHostname(String hostname) {
        this.hostname = hostname;
    }

    protected int getPort() {
        return port;
    }

    protected void setPort(int port) {
        this.port = port;
    }

    protected int getTimeout() {
        return timeout;
    }

    protected void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    protected String getCipherSuites() {
        return cipher_suites;
    }

    protected void setCipherSuites(String cipher_suites) {
        this.cipher_suites = cipher_suites;
    }

    protected String getTlsVersion() {
        return version;
    }

    protected void setTLSVersion(String version) {
        this.version = version;
    }

    protected String getCompressionMethod() {
        return compression_method;
    }

    protected void setCompressionMethod(String compression_method) {
        this.compression_method = compression_method;
    }

    protected String getMessageDir() {
        return message_dir;
    }

    protected void setMessageDir(String message_dir) {
        this.message_dir = message_dir;
    }
}
