# AssinadorPDF
Este projeto foi desenvolvido utilizando a IDE Netbeans 8.2, utilizando a versão 8 do JAVA, sob atualização 251.

Para executar o programa, você deve:
1) Importar o projeto para a sua IDE Netbeans
2) Certificar de que as seguintes bibliotecas estão importadas ao projeto: itextpdf-5.4.5.jar, bcpkix-jdk15on-1.50.jar, bcprov-jdk15on-150.jar.
3) Localizar o arquivo AssinadorPDF.java
4) Atualizar os atributos do método main, para os valores que deseja utilizar.
5) Executar a aplicação.

Obs: Por padrão, o programa vai retornar o arquivo PDF assinado para o mesmo diretório de origem do documento. O PDF assinado receberá o nome de "targetFile.pdf".


Sobre os atributos do método main:
  String caminhoArquivo = "C:\\arquivos\\";
  //aqui você deve colocar uma String com o caminho da pasta em que o arquivo PDF que você quer assinar, vai estar.
  
  String nomeArquivo = "teste.pdf";
  //aqui você deve colocar uma String com o nome do arquivo PDF que você quer assinar.
  
  String caminhoDriverDLL = "C:\\Windows\\System32\\aetpksse.dll";
  //aqui você deve colocar uma STRING com o caminho do driver do certificado digital que você está usando. Neste caso, estou usando um certificado Certisign, caso você esteja utilizando-o, não precisa modificar.
  
  String senhaCard = "1234";
  //aqui você deve colocar uma STIRNG com a senha do certificado digital
  
  Boolean finalizaDocumento = Boolean.TRUE;     
  //aqui você deve colocar um boolean, informando se o documento vai ser assinado por apenas um certificado (assim ele é finalizado, ou seja, não permite mais a assinatura) ou se ele vai ser assinado por mais de uma pessoa (neste caso o documento é assinado, mas ainda permite modificações - ou seja, fica sem certificação).
