package tsi.prober;

public interface InputSymbol {
    String CH = "ClientHelloExtendedRenegotiation";
    String CERT = "CertificateEmpty";
    String CKE = "ClientKeyExchange";
    String CKE_ECDH = CKE + "ECDH";
    String CKE_RSA = CKE + "RSA";
    String CKE_DH = CKE + "DH";
    String CCS = "ChangeCipherSpec";
    String FIN = "Finished";
    String ALERT = "AlertWarningCloseNotify";
    String APP = "ApplicationDataEmpty";
}
