/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package assinadorpdf;

import java.io.File;
import java.nio.file.Files;

/**
 *
 * @author thiag
 */
public class AssinadorPDF {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws DocumentSignException, Exception {
        SignerLibrary a = new SignerLibrary();
        String caminhoArquivo = "C:\\arquivos\\teste.pdf";
        String caminhoDriverDLL = "C:\\Windows\\System32\\aetpksse.dll";
        String senhaCard = "1234";
        Boolean finalizaDocumento = Boolean.TRUE;
        
        File file = new File(caminhoArquivo);
        
        byte[] f = Files.readAllBytes(file.toPath());
        
        a.inicializar(caminhoArquivo, f, caminhoDriverDLL , senhaCard, finalizaDocumento);
    }
    
}
