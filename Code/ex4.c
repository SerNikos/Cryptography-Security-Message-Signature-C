//NIKOLAOS SERGIS PADA EX 4

#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
 char * number_str = BN_bn2hex(a);
 printf("%s %s\n", msg, number_str);
 OPENSSL_free(number_str);
}
int main ()
{

 BN_CTX *ctx = BN_CTX_new();//a temporary struct to help with the computational process of large numbers
 BIGNUM *n = BN_new(); //n is the result of the multiplication of two first numbers p*q
 BIGNUM *d = BN_new(); //private key
 BIGNUM *M1 = BN_new();//first message
 BIGNUM *M2 = BN_new();//second message in which we changed 2 letters
 BIGNUM *resM1 = BN_new();//signature for message 1
 BIGNUM *resM2 = BN_new();//signature for message 2


BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"); //n will is the result of the multiplication of two first numbers p*q
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D"); //private key
BN_hex2bn(&M1, "74686973206973206120736563726574206d657373616765"); // hex encode for "this is a secret message"
BN_hex2bn(&M2, "74686973206973206120736563726574204d65737361676532"); // hex encode for "this is a secret Message2"

//Calculatin Signatures
BN_mod_exp(resM1, M1, d, n, ctx);
BN_mod_exp(resM2, M2, d, n, ctx);

//Printing the two signatures
 printBN("Signatures of Message 1 is", resM1);
 printBN("Signatures of Message 2 is", resM2);

    return 0;
}
