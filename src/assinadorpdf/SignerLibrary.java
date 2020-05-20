package assinadorpdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.net.Authenticator;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.tsp.TimeStampTokenInfo;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import com.itextpdf.text.pdf.security.TSAInfoBouncyCastle;

/**
 * Dialog for choosing PKCS#11 implementation library file and PIN code for
 * accessing the smart card. Allows the user to choose a PKCS#11 library file
 * (.dll / .so) and enter a PIN code for the smart card. The last used library
 * file name is remembered in the config file called
 * ".smart_card_signer_applet.config" located in the user's home directory in
 * order to be automatically shown the next time when the same user accesses
 * this dialog.
 *
 * This file is part of NakovDocumentSigner digital document signing framework
 * for Java-based Web applications: http://www.nakov.com/documents-signing/
 *
 * Copyright (c) 2005 by Svetlin Nakov - http://www.nakov.com All rights
 * reserved. This code is freeware. It can be used for any purpose as long as
 * this copyright statement is not removed or modified.
 */
public class SignerLibrary {

    private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
    private static final String X509_CERTIFICATE_TYPE = "X.509";
    private static final String CERTIFICATION_CHAIN_ENCODING = "PkiPath";
    private static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";
    //private static SignerApplet applet;
    private KeyStore userKeyStore = null;
    private PrivateKeyAndCertChain privateKeyAndCertChain = null;
    private CertificationChainAndSignatureBase64 signingResult = new CertificationChainAndSignatureBase64();
    private Certificate[] certChain = null;
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private X509Certificate certificate = null;
    private String name;

    private Provider pkcs11Provider;

    private boolean mResult = false;

    private byte[] file;
    //private byte[] cert;

    /**
     * Initializes the dialog - creates and initializes its GUI controls.
     *
     * @throws DocumentSignException
     */
    public byte[] inicializar(String filename, byte[] file, String certname, String pin, Boolean finalizarDocumento) throws DocumentSignException {
        try {
            System.out.println("Iniciando Assinador");
            this.file = file;
            //this.cert = cert;
            byte[] retorno = signButton_actionPerformed(filename, certname, pin, finalizarDocumento);
            System.out.println("Saindo do Assinador");
            return retorno;
        } catch (Exception e1) {
            throw new DocumentSignException(e1.getMessage());
        }
    }

    private byte[] signButton_actionPerformed(String filename, String certname, String pin, Boolean finalizarDocumento) throws DocumentSignException {
        mResult = true;
        return signFile(filename, certname, pin, finalizarDocumento);

    }

    private byte[] signFile(String aFileName, String certname, String pin, Boolean finalizarDocumento) throws DocumentSignException {

        // Load the file for signing
        String pinCode = "";
        pinCode = pin;
        if (pinCode == null || pinCode.isEmpty()) {
            throw new DocumentSignException("PinCode deve ser preenchido.");
        }

        try {
            return signDocument(aFileName, certname, pinCode, finalizarDocumento);
        } catch (Exception e) {
            throw new DocumentSignException(e.getMessage());
        }

    }

    private byte[] signDocument(String aFileName, String certname, String aPinCode, Boolean finalizarDocumento) throws DocumentSignException, DocumentException, IOException {
        // Load the keystore from the smart card using the specified PIN code
        extractCertificateInformation(certname, aPinCode);
        PdfReader reader = null; // responsável por criar o documento PDF e as áreas de assinatura
        OutputStream fow = null;
        PdfStamper stamper = null; // responsável por criar o documento PDF e as áreas de assinatura
        FileInputStream fis = null;
        ByteArrayOutputStream bos = null;
        byte[] bytes = null;

        String filename = aFileName;

        try {

            //Aqui o nome do arquivo é mudado acrescentando _signed para indicar que ele foi assinado
            filename = aFileName.substring(0, aFileName.length() - 4);
            if (filename.contains("_signed")) {
                filename = filename.substring(0, filename.indexOf("_signed"));
            }
            
            ByteArrayOutputStream out = criarStampas(reader); //cria áreas no docmento para incluir as assinaturas
            filename += "_signed.pdf";

            File fileToWrite = File.createTempFile(filename, null); // cria um arquivo temporário que recebe o arqiuvo + assinatura
            reader = new PdfReader(out.toByteArray()); // cria o PdfReader com base no retorno do método de estampas.

            fow = new FileOutputStream(fileToWrite);
            stamper = PdfStamper.createSignature(reader, fow, '\0', null, true); // onde é criada a assinatura; reader = pdf a ser assinado; fow = onde será salvo o pdf assinado; informa que quer manter o mesmo documento; informa se poderá assinar documento mais de uma vez
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();


            //A seguir, é definido se o documento será assinado apenas validando (sem certificação) ou se o documento será certificado
            if (finalizarDocumento) {
                appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
            } else {
                appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
            }

            appearance.setSignDate(Calendar.getInstance());

            
            //as linhas a seguir são apenas para caso seja necessário usar um Proxy
//            Authenticator.setDefault(new ProxyAuthenticator("marcus.mazzo", "marcus147"));
//            System.setProperty("http.proxyHost", "prx.semace.com.br");
//            System.setProperty("http.proxyPort", "3128");

            String tsaUrl = "http://tsa.starfieldtech.com";
            TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle(tsaUrl);
            tsaClient.setTSAInfo(new TSAInfoBouncyCastle() {
                @Override
                public void inspectTimeStampTokenInfo(TimeStampTokenInfo info) {
                    System.out.println(info.getGenTime()); //exibe no console a data obtida pelo provedor de data
                }
            }
            );

            ExternalDigest digest = new BouncyCastleDigest(); //utilizado para setar a assinatura
            OcspClient ocspClient = new OcspClientBouncyCastle(); //validação do certificado de forma online
            ExternalSignature signature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, pkcs11Provider.getName()); // cria a assinatura
            MakeSignature.signDetached(appearance, digest, signature, certChain, null, ocspClient, tsaClient, 0, CryptoStandard.CMS); // coloca a assinatura no documento

            fis = new FileInputStream(fileToWrite);
            byte[] buffer = new byte[fis.available()];
            fis.read(buffer);
            
            File targetFile = new File("C:\\arquivos\\targetFile.pdf");
            OutputStream outStream = new FileOutputStream(targetFile);
            outStream.write(buffer);
            
//            bos = new ByteArrayOutputStream();
//            byte[] buf = new byte[1024];
//            for (int readNum; (readNum = fis.read(buf)) != -1;) {
//                bos.write(buf, 0, readNum); //no doubt here is 0
//            }
//            bytes = bos.toByteArray();

        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            if (stamper != null) {
                stamper.close();
            }

            if (fow != null) {
                fow.close();
            }

            if (reader != null) {
                reader.close();
            }

            if (bos != null) {
                bos.close();
            }

            if (fis != null) {
                fis.close();
            }
        }

        System.out.println("Documento Assinado com sucesso");
        return bytes;
    }
    
    public void extractCertificateInformation(String certname, String aPinCode) throws DocumentSignException {
        try {
            userKeyStore = loadKeyStoreFromSmartCard(certname, aPinCode);
        } catch (Exception ex) {
            String errorMessage = "Erro ao ler repositório do smart card. \n"
                    + "Possíveis erros: \n"
                    + "- Smart Card não conectado. \n"
                    + "- Biblioteca Inválida. \n"
                    + "- Código PIN incorreto. \n";
            throw new DocumentSignException(errorMessage, ex);
        }

        // Get the private key and its certification chain from the keystore
        try {
            privateKeyAndCertChain = getPrivateKeyAndCertChain(userKeyStore);
        } catch (GeneralSecurityException gsex) {
            String errorMessage = "Erro. Favor verificar senha";
            throw new DocumentSignException(errorMessage, gsex);
        }

        // Check if the private key is available
        privateKey = privateKeyAndCertChain.mPrivateKey;
        if (privateKey == null) {
            String errorMessage = "Erro: chave privada do smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Check if public key is available
        publicKey = privateKeyAndCertChain.mPublicKey;
        if (publicKey == null) {
            String errorMessage = "Erro: chave pública do smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Check if X.509 certification chain is available
        certChain = privateKeyAndCertChain.mCertificationChain;
        if (certChain == null) {
            String errorMessage = "Erro: certificado do smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Create the result object
        // Save X.509 certification chain in the result encoded in Base64
        try {
            signingResult.mCertificationChain = encodeX509CertChainToBase64(certChain);
        } catch (CertificateException cee) {
            String errorMessage = "Certificado inválido.";
            throw new DocumentSignException(errorMessage);
        }

        certificate = (X509Certificate) privateKeyAndCertChain.certificate;
        ExtratorUtil.parse(certificate);
        name = ExtratorUtil.pfDados;
    }
    
    private KeyStore loadKeyStoreFromSmartCard(String certName, String aSmartCardPIN) throws GeneralSecurityException, IOException {
        // First configure the Sun PKCS#11 provider. It requires a stream (or file)
        // containing the configuration parameters - "name" and "library".
        File file = new File(certName);
        if (!file.exists()) {
            throw new IOException("Arquivo certificado não localizado");
        }
        String pkcs11ConfigSettings = "";

        pkcs11ConfigSettings = "name = SmartCard\n" + "library = " + file.getAbsolutePath();

        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        // Instantiate the provider dynamically with Java reflection
        try {
            Class<?> sunPkcs11Class = Class.forName(SUN_PKCS11_PROVIDER_CLASS);
            Constructor<?> pkcs11Constr = sunPkcs11Class.getConstructor(
                    java.io.InputStream.class);
            pkcs11Provider = (Provider) pkcs11Constr.newInstance(confStream);
            Security.addProvider(pkcs11Provider);
        } catch (Exception e) {
            throw new KeyStoreException("Can initialize Sun PKCS#11 security "
                    + "provider. Reason: " + e.getCause().getMessage());
        } finally {
            confStream.close();
        }

        // Read the keystore form the smart card
        char[] pin = aSmartCardPIN.toCharArray();
        KeyStore keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE);
        keyStore.load(null, pin);
        return keyStore;
    }

    private ByteArrayOutputStream criarStampas(PdfReader reader) throws DocumentException, IOException, DocumentSignException {
        Integer lowerX = 0;
        Integer upperX = 50;
        reader = new PdfReader(file);
        Integer pageCount = reader.getNumberOfPages();

        AcroFields af = reader.getAcroFields();
        String postname = "";
        if (af != null) {
            // Search of the whole signature
            ArrayList<String> names = af.getSignatureNames();
            if (names != null && !names.isEmpty()) {
                Integer index = upperX;
                upperX = upperX * (names.size());
                lowerX = lowerX + upperX;
                upperX += index;
                postname = String.valueOf(names.size());
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        PdfStamper stp1 = new PdfStamper(reader, out, '\3', true);

        PdfFormField sig = PdfFormField.createSignature(stp1.getWriter());
        sig.setWidget(new com.itextpdf.text.Rectangle(lowerX, 0, upperX, 25), null);
        sig.setFlags(PdfAnnotation.FLAGS_PRINT);
        sig.put(PdfName.DA, new PdfString("/Helv 0 Tf 0 g"));
        sig.setFieldName(name);
        sig.setPage(1);

        for (int i = 1; i <= pageCount; i++) {
            stp1.addAnnotation(sig, i);
        }

        stp1.close();
        out.close();
        return out;
    }

    

    private PrivateKeyAndCertChain getPrivateKeyAndCertChain(KeyStore aKeyStore) throws GeneralSecurityException {
        Enumeration<?> aliasesEnum = aKeyStore.aliases();
        if (aliasesEnum.hasMoreElements()) {
            String alias = (String) aliasesEnum.nextElement();
            Certificate[] certificationChain = aKeyStore.getCertificateChain(alias);
            PrivateKey privateKey = (PrivateKey) aKeyStore.getKey(alias, null);
            PrivateKeyAndCertChain result = new PrivateKeyAndCertChain();
            result.mPrivateKey = privateKey;
            result.mCertificationChain = certificationChain;
            result.certificate = aKeyStore.getCertificate(alias);
            result.mPublicKey = result.certificate.getPublicKey();
            return result;
        }

        throw new KeyStoreException("The keystore is empty!");
    }

    private String encodeX509CertChainToBase64(Certificate[] aCertificationChain) throws CertificateException {
        List<Certificate> certList = Arrays.asList(aCertificationChain);
        CertificateFactory certFactory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        CertPath certPath = certFactory.generateCertPath(certList);
        byte[] certPathEncoded = certPath.getEncoded(CERTIFICATION_CHAIN_ENCODING);
        String base64encodedCertChain = Base64Utils.base64Encode(certPathEncoded);
        return base64encodedCertChain;
    }

    /**
     * Data structure that holds a pair of private key and certification chain
     * corresponding to this private key.
     */
    static class PrivateKeyAndCertChain {

        public PrivateKey mPrivateKey;
        public Certificate[] mCertificationChain;
        public Certificate certificate;
        public PublicKey mPublicKey;
    }

    /**
     * Data structure that holds a pair of Base64-encoded certification chain
     * and digital signature.
     */
    static class CertificationChainAndSignatureBase64 {

        public String mCertificationChain = null;
        public String mSignature = null;
    }

//    /**
//     * Exception class used for document signing errors.
//     */
//    public static SignerApplet getApplet() {
//        return applet;
//    }
//
//    public static void setApplet(SignerApplet applet) {
//        SignerLibrary.applet = applet;
//    }

}
