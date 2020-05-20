package assinadorpdf;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

@SuppressWarnings("deprecation")
public class ExtratorUtil {

    public static final DERObjectIdentifier OID_PF_DADOS_TITULAR = new DERObjectIdentifier("2.16.76.1.3.1");
    public static final DERObjectIdentifier OID_PJ_RESPONSAVEL = new DERObjectIdentifier("2.16.76.1.3.2");
    public static final DERObjectIdentifier OID_PJ_DADOS_RESPONSAVEL = new DERObjectIdentifier("2.16.76.1.3.4");
    public static final DERObjectIdentifier OID_CRL = new DERObjectIdentifier("2.5.29.31");
    public static String pfDados;

    public static String getPFDados(X509Certificate cert) throws DocumentSignException {
        ExtratorUtil.parse(cert);
        return pfDados;
    }

    @SuppressWarnings("unused")
    public static void parse(X509Certificate cert) throws DocumentSignException {
        try {

            Collection<?> col = X509ExtensionUtil.getSubjectAlternativeNames(cert);

            for (Object obj : col) {

                if (obj instanceof ArrayList) {

                    ArrayList<?> lst = (ArrayList<?>) obj;

                    Object value = lst.get(1);
                    //System.out.println(value.getClass());

                    if (value instanceof DLSequence) {

                        /**
                         * DER Sequence ObjectIdentifier Tagged DER Octet String
                         */
                        DLSequence seq = (DLSequence) value;

                        DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0);
                        DERTaggedObject tagged = (DERTaggedObject) seq.getObjectAt(1);
                        String info = null;

                        ASN1Primitive derObj = tagged.getObject();

                        if (derObj instanceof DEROctetString) {
                            DEROctetString octet = (DEROctetString) derObj;
                            info = new String(octet.getOctets());
                        } else if (derObj instanceof DERPrintableString) {
                            DERPrintableString octet = (DERPrintableString) derObj;
                            info = new String(octet.getOctets());
                        } else if (derObj instanceof DERUTF8String) {
                            DERUTF8String str = (DERUTF8String) derObj;
                            info = str.getString();
                        }

                        if (oid.equals(OID_PF_DADOS_TITULAR) || oid.equals(OID_PJ_DADOS_RESPONSAVEL)) {
                            String nascimento = info.substring(0, 8);

                            String nis = info.substring(19, 30);
                            String rg = info.substring(30, 45);
                            if (!rg.equals("000000000000000")) {
                                String ufExp = info.substring(45, 50);
                            }
                        }

                        if (oid.equals(OID_CRL)) {
                            System.out.println(info);
                        }

                    } else {
                        System.out.println("Valor desconhecido: " + value);
                    }
                }

            }
        } catch (Exception e) {
            throw new DocumentSignException(e.getMessage());
        }

    }
}
