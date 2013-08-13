package au.com.inpex.mapping;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.lang.Integer;
import java.security.SecureRandom;
import java.util.Date;

//import org.apache.commons.io.IOUtils;


// PGP library packages (Bouncy Castle)
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;


// SAP mapping packages
import com.sap.aii.mapping.api.AbstractTransformation;
import com.sap.aii.mapping.api.StreamTransformationException;
import com.sap.aii.mapping.api.TransformationInput;
import com.sap.aii.mapping.api.TransformationOutput;   

/*
 * This is a SAP NetWeaver PI Java Mapping Class. It can be used in an Operation Mapping to perform PGP
 * encryption of a message or sub-node of a messages. The BouncyCastle library is used:
 * www.bouncycastle.org - based on version 1.47.
 * 
 * A decryption mapping can be easily created using this as a base.
 * 
 * See my SCN blog for details:
 *     http://scn.sap.com/community/pi-and-soa-middleware/blog/2012/12/14/pgp-encrypting-part-of-an-xml-message 
 * 
 * Mapping Parameters are used for configuration entries as follows:
 * 
 *      - PUBLICKEY_FILENAME This defines the public key file full path specification 
 *      - COMPRESS_TYPE This defines the compression type - see package org.bouncycastle.openpgp.PGPCompressedData
 *        for allowed values (PGPCompressedData.ZIP). Uncompressed = 0; ZIP = 1; BZIP2 = 3; ZLIB = 2.
 *      - ENCRYPT_TYPE This defines the compression algorithm to use - see package org.bouncycastle.openpgp.PGPEncryptedData
 *        (PGPEncryptedData.CAST5) for the allowed values. Null = 0; IDEA = 1; TRIPLE_DES = 2; CAST = 3; BLOWFISH = 4; 
 *        SAFER = 5; DES = 6; AES128 = 7; AES192 = 8; AES256 = 9; TWO_FISH = 10.
 *      - ASCIIARMORED Generates and ASCII armored output
 *      - INTEGRITYCHECK This performs an integrity check on the data
 * 
 * 
 * "transform" is the entry point called by the SAP NetWeaver PI mapping runtime.
 * For local testing a main method is provided at the bottom of the class. It is ignored by the PI
 * mapping runtime.
 * 
 */
public class MapPGP extends AbstractTransformation {
    private static String publicKeyFilename = "";
    @SuppressWarnings("unused")
    private static int compressType = 1;
    private static int encryptType = 3;
    private static boolean asciiArmored = false;
    private static boolean integrityCheck = false;


    public void transform(TransformationInput arg0, TransformationOutput arg1) 
            throws StreamTransformationException {

        //Get mapping parameters
        publicKeyFilename = arg0.getInputParameters().getString("PUBLICKEY_FILENAME");
        compressType = new Integer(arg0.getInputParameters().getString("COMPRESS_TYPE")).intValue();
        encryptType = new Integer(arg0.getInputParameters().getString("ENCRYPT_TYPE")).intValue();
        asciiArmored = new Boolean(arg0.getInputParameters().getString("ASCII_ARMORED")).booleanValue();
        integrityCheck = new Boolean(arg0.getInputParameters().getString("INTEGRITY_CHECK")).booleanValue();

        //testing - simply copy input to output
        //try {
        //	FileOutputStream fos = new FileOutputStream(new File("\\\\dc1spiddvw01\\sapmnt\\PID\\SYS\\global\\PGPkeys\\sap_to_fpe\\test.xml"));
        //	IOUtils.copy(arg0.getInputPayload().getInputStream(), fos);
        //}
        //catch (FileNotFoundException fnf) {
        //	throw new StreamTransformationException("Stream File not found exception." + fnf.getMessage());
        //}
        //catch (IOException io) {
        //	throw new StreamTransformationException("Stream IOException." + io.getMessage());
        //}
        //end testing

        execute(arg0.getInputPayload().getInputStream(), arg1.getOutputPayload().getOutputStream());
    }

    public void execute(InputStream is, OutputStream os) throws StreamTransformationException {

        //InputStream keyIn = getClass().getResourceAsStream(PUBLICKEY_FILENAME); //this is for reading a file inside the jar
        try {
            InputStream keyIn = new FileInputStream(publicKeyFilename);
            if (asciiArmored) {
                os = new ArmoredOutputStream(os);
            }

            String plainText = getInputXML(is);
            byte[] encryptedBytes = encryptString(plainText, keyIn);	
            PrintStream ps = new PrintStream(os);

            //Build up the output xml message. No point using the DOM as its just one field.
            ps.print("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ns0:MT_PersonInsert_PGP xmlns:ns0=\"urn:inpex.com.au:hr:persons\"><pgp_string>");
            String encoded = javax.xml.bind.DatatypeConverter.printBase64Binary(encryptedBytes);            	
            ps.print(encoded);
            ps.print("</pgp_string></ns0:MT_PersonInsert_PGP>");
            ps.flush();			
        }
        catch (FileNotFoundException fnfe) {
            throw new StreamTransformationException("Public Key file not found: " + publicKeyFilename + ". Check mapping parameter." + fnfe.getMessage());
        }
        catch (IOException io) {
            throw new StreamTransformationException("Stream IOException." + io.getMessage());
        }
        catch (Exception e) {
            throw new StreamTransformationException("Encryption IOException." + e.getMessage());
        }
    }

    private String getInputXML(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        char[] cbuf = new char[1024];
        int charsRead;
        while ((charsRead = reader.read(cbuf)) != -1) {
            sb.append(cbuf, 0, charsRead);
        }
        reader.close();
        return sb.toString();
    }

    /*
     * Encrypt the given plaintext string.
     * Note: this does not requires the use of a temp file as BcPGP.encryptFile() does.
     */
    private byte[] encryptString(String plainText, InputStream keyIn) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PGPPublicKey encKey = BcPGP.readPublicKey(keyIn);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(1);
        writeStringToLiteralData(comData.open(bOut), 'b', plainText);
        comData.close();

        BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(encryptType);
        dataEncryptor.setWithIntegrityPacket(integrityCheck);
        dataEncryptor.setSecureRandom(new SecureRandom());

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

        byte[] outBytes = bOut.toByteArray();
        OutputStream cOut = encryptedDataGenerator.open(out, outBytes.length);
        cOut.write(outBytes);
        cOut.close();
        out.close();

        System.out.println("data encrypted");

        return out.toByteArray();
    }

    private void writeStringToLiteralData(OutputStream out, char fileType, String plainText) throws Exception {
        byte[] plainTextBytes = plainText.getBytes("Cp1252");   // to-do: remove hard-coded character format
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, "clearText", plainTextBytes.length, new Date());
        pOut.write(plainTextBytes);
        lData.close();
    }

    /*
     * Add a PI mapping trace entry.
     */
    public void trace(String message) {
        try {
            getTrace().addInfo(message);
        }
        catch (Exception e) { }	//ignore	
    }

    /*
     * For local testing only - not called by the SAP NetWeaver PI mapping runtime.
     */
    public static void main(String[] args) {
        try {
            publicKeyFilename = "C:\\Users\\jscott\\Documents\\PI\\FPe\\pub.asc";
            compressType = 1;  //PGPCompressedData.ZIP
            encryptType = 3;   //PGPEncryptedData.CAST5
            asciiArmored = false;
            integrityCheck = false;

            InputStream in = new FileInputStream(new File("C:\\Users\\jscott\\Documents\\PI\\FPe\\in.xml"));
            OutputStream out = new FileOutputStream(new File("C:\\Users\\jscott\\Documents\\PI\\FPe\\out.xml"));
            MapPGP mappgp = new MapPGP();
            mappgp.execute(in, out);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
