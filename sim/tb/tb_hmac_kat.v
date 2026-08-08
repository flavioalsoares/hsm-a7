`timescale 1ns/1ps
//
// tb_hmac_kat -- NAO IMPLEMENTADO, e provavelmente nunca sera.
//
// Este esqueleto ficou de um plano em que o HMAC seria um core em RTL. Nao
// e: HMAC-SHA-256 e FIRMWARE (fw/src/sha.c) sobre a funcao de compressao
// que o CFS entrega. Nao ha nada em Verilog para exercitar aqui, e um
// testbench que instancia um modulo que nao existe nao e um teste pendente,
// e uma pergunta mal formulada.
//
// Onde o HMAC E testado, contra o RFC 4231:
//
//   POST        tres casos, no boot e a cada SELFTEST, em hardware.
//               Inclui o caso 6 -- chave MAIOR que o bloco -- que e o ramo
//               que quase toda implementacao caseira esquece.
//               Ver fw/src/kat.c e fw/include/kat_vectors.h.
//
//   host        python3 host/hsmtool.py hmac <chave> <mensagem>
//
// Se um dia o HMAC virar core em RTL -- para vazao, na fase 7 -- este
// arquivo volta a fazer sentido. Ate la, deletar seria perder o registro
// de por que ele nao existe.
//
module tb_hmac_kat;
  initial begin
    $display("[tb_hmac_kat] NAO IMPLEMENTADO -- HMAC e firmware, coberto pelo POST");
    $finish;
  end
endmodule
