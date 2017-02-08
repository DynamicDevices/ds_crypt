// Includes

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>

#include "ds_crypt.h"

// Defines

// Statics

/* Key */

// Generated from atmospheric noise at http://www.random.org/bytes
static unsigned char key[] = { 0x15,0x3d,0x98,0x57,0x6f,0x80,0x52,0x85,0x73,0x9c,0x0d,0x99,0x10,0xf1,0x7f,0xc2,0x11,0x5c,0x05,0xac,0xc9,0x52,0x9f,0xa6,0x92,0x26,0x31,0x76,0x8a,0x8b,0x4d,0x84 };
static unsigned char iv[] = { 0x53,0x12,0x77,0xeb,0x11,0xaa,0xd1,0x6d,0x1a,0x14,0x2d,0x75,0xb8,0x6e,0x56,0x03 };

/* IV */

// Prototypes
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

// Functions

int main(int argc, char *argv[])
{
    unsigned char *pInputText;
    unsigned char *pOutputText;
    unsigned char *pKey = key;
    unsigned char *pIV = iv;
    char *pInputFile = "input.txt";
    char *pOutputFile = "output.txt";

    int c;
    int opt_count = 0;

    int output_len = 0;

    bool bDecrypt = false;
    bool bVerbose = false;
    bool bShowHelp = false;

    FILE *pIn;
    FILE *pOut;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Parse in the options
    while( ( c = getopt( argc, argv, "k:s:i:o:dc:v?") ) != -1)
    {
	opt_count++;

 	switch(c)
	{
	case 'k' :
		pKey = (unsigned char *)strdup(optarg);
		break;
	case 's' :
		pIV = (unsigned char *)strdup(optarg);
		break;
	case 'i' :
		pInputFile = strdup(optarg);
		break;
        case 'o' :
		pOutputFile = strdup(optarg);
		break;
	case 'd' :
		bDecrypt = true;
		break;
	case 'c' :
		printf("Cipher not implemented\r\n");
		return -1;
	case 'v' :
		bVerbose = true;
		break;
        default:
	case '?':
		bShowHelp = true;
		break;
	}
    }

    if(opt_count == 0)
	bShowHelp = true;

    if(bShowHelp)
    {
	printf("ds_crypt v%s - de/encrypt a file using AES 256 CBC\n", VERSION);
	printf("Syntax: ds_crypt [-d] [-v] [-k key] [-s iv] [-i input_file] [-i output_file]\n");
	printf("-d decrypt (otherwise encrypt)\n");
	printf("-v verbose\n");
	printf("-k key\n");
	printf("-s initialisation vector\n");
	printf("-i input file (defaults to input.txt)\n");
	printf("-o output file (defaults to output.txt)\n");
        return -1;
    }

    if(bVerbose)
    {
	if(bDecrypt)
		printf("Decrypting\n");
	else
		printf("Encrypting\n");

	printf("Input File: %s\n", pInputFile);
	printf("Output File: %s\n", pOutputFile);

        printf("Key is:\n");
        BIO_dump_fp(stdout, (const char *)pKey, strlen( (const char *)pKey));
        printf("IV is:\n");
        BIO_dump_fp(stdout, (const char *)pIV, strlen( (const char *)pIV));
    }

    pIn = fopen((const char *)pInputFile, "rb");
    if(!pIn)
    {
      fprintf(stderr, "Cannot open input file %s\n", pInputFile);
      return -1;
    }

    fseek(pIn, 0, SEEK_END); // seek to end of file
    long filesize = ftell(pIn); // get current file pointer
    fseek(pIn, 0, SEEK_SET); // seek back to beginning of file

    pInputText = malloc(filesize);
    fread(pInputText, filesize, 1, pIn);
    fclose(pIn);

    // Make output buffer big enough
    pOutputText = malloc(filesize*2);

    if(bVerbose)
    {
        printf("Input text is:\n");
        BIO_dump_fp(stdout, (const char *)pInputText, filesize);
    }

    pOut = fopen((const char *)pOutputFile, "wb");
    if(!pOut)
    {
      fprintf(stderr, "Cannot open output file %s\n", pOutputFile);
      return -1;
    }

    if(!bDecrypt)
    {
      /* Encrypt the plaintext */
      output_len = encrypt(pInputText, filesize, pKey, pIV, pOutputText);
    }
    else
    {
      /* Decrypt the ciphertext */
      output_len = decrypt(pInputText, filesize, pKey, pIV, pOutputText);
    }

    if(output_len < 0)
    {
        /* Verify error */
        printf("Failed!\n");
    }
    else
    {
      /* Add a NULL terminator. We are expecting printable text */
      pOutputText[output_len] = '\0';

      if(bVerbose)
      {
        printf("Output text (%d)is:\n", output_len);
        BIO_dump_fp(stdout, (const char *)pOutputText, output_len);
      }

      // Write to file
      fwrite(pOutputText, output_len, 1, pOut);

    }

    // Close the output file
    fclose(pOut);

    /* Remove error strings */
    ERR_free_strings();

    // All done - success!
    return 0;
}

void handleErrors(void)
{
    unsigned long errCode;

    fprintf(stderr, "An error occurred\n");
    while( (errCode = ERR_get_error() ) )
    {
        char *err = ERR_error_string(errCode, NULL);
        fprintf(stderr, "%s\n", err);
    }
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}
