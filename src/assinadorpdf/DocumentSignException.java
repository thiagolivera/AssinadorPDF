/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package assinadorpdf;

/**
 *
 * @author thiag
 */
public class DocumentSignException extends Exception {

    public DocumentSignException(String e) {
        System.out.println(e);
    }
    
    public DocumentSignException(String e, Exception e1) {
        System.out.println(e);
    }
    
}
