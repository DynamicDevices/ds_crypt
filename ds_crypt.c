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

#include "keys.h"

/* IV */

// Prototypes
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int unescape(char* str);

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

    int input_len = 0;
    int output_len = 0;
    int key_size = sizeof(key);
    int iv_size = sizeof(iv);

    bool bDecrypt = false;
    bool bVerbose = false;
    bool bShowHelp = false;
    bool bUseCmdLineText = false;
    bool bOutputToCmdLine = true;
    bool bBareOutput = false;

    FILE *pIn;
    FILE *pOut;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Parse in the options
    while( ( c = getopt( argc, argv, "k:s:i:o:dc:t:bv?") ) != -1)
    {
	opt_count++;

 	switch(c)
	{
	case 'k' :
		pKey = (unsigned char *)strdup(optarg);
                key_size = strlen((const char *)pKey);
		break;
	case 's' :
		pIV = (unsigned char *)strdup(optarg);
                iv_size = strlen((const char *)pIV);
		break;
	case 'i' :
		pInputFile = strdup(optarg);
		break;
	case 't' :
        {
		char *pCopy = strdup(optarg);
		input_len = unescape(pCopy);
		pInputText = (unsigned char *)pCopy;
		bUseCmdLineText = true;
		break;
        }
        case 'o' :
		pOutputFile = strdup(optarg);
                bOutputToCmdLine = false;
		break;
	case 'd' :
		bDecrypt = true;
		break;
	case 'c' :
		printf("Cipher not implemented\r\n");
		return -1;
	case 'b' :
		bBareOutput = true;
		break;
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
	printf("-b bare output mode (hex bytes only)\n");
	printf("-k key\n");
	printf("-s initialisation vector\n");
	printf("-t \"input text\" (can be null terminated with \\0)\n");
	printf("-i input file (defaults to input.txt)\n");
	printf("-t 'input text' (instead of file)\n");
	printf("-o output file (defaults to command line)\n");
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
        BIO_dump_fp(stdout, (const char *)pKey, key_size);
        printf("IV is:\n");
        BIO_dump_fp(stdout, (const char *)pIV, iv_size);
    }

    if(!bUseCmdLineText)
    {
      pIn = fopen((const char *)pInputFile, "rb");
      if(!pIn)
      {
        fprintf(stderr, "Cannot open input file %s\n", pInputFile);
        return -1;
      }

      fseek(pIn, 0, SEEK_END); // seek to end of file
      input_len = ftell(pIn); // get current file pointer
      fseek(pIn, 0, SEEK_SET); // seek back to beginning of file

      pInputText = malloc(input_len);
      fread(pInputText, input_len, 1, pIn);
      fclose(pIn);
    }

    // Make output buffer big enough
    pOutputText = malloc(input_len*2);

    if(bVerbose)
    {
        printf("Input text is:\n");
        BIO_dump_fp(stdout, (const char *)pInputText, input_len);
    }

    if(!bDecrypt)
    {
      /* Encrypt the plaintext */
      output_len = encrypt(pInputText, input_len, pKey, pIV, pOutputText);
    }
    else
    {
      /* Decrypt the ciphertext */
      output_len = decrypt(pInputText, input_len, pKey, pIV, pOutputText);
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

      if(bOutputToCmdLine)
      {
	if(bBareOutput)
	{
	  for(int i = 0; i < output_len;i++)
	    printf("%02X", pOutputText[i]);
          printf("\n");
	}
	else
	{
          BIO_dump_fp(stdout, (const char *)pOutputText, output_len);
	}
      }
      else
      {
        pOut = fopen((const char *)pOutputFile, "wb");
        if(!pOut)
        {
          fprintf(stderr, "Cannot open output file %s\n", pOutputFile);
          free(pInputText);
          return -1;
        }

        // Write to file
        fwrite(pOutputText, output_len, 1, pOut);

        // Close the output file
        fclose(pOut);
      }
    }

    // Free allocated memory
    free(pInputText);
    free(pOutputText);

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

// Unescapes 'str' in place, collapsing it back on itself, and
// returns the resulting length of the collapsed buffer.  Handles
// mid-buffer nul characters (0x00).  You can easily add your own
// special escape sequences if you wish.  Just be sure that no escape
// sequence translates into more characters than it takes to encode
// the escape sequence itself in the original string.
int unescape(char* str)
{
    char *out, *in;
    int len=0;
    in = out = str; // both start at the same place
    while(*in)
    {
        char c = *in++;
        if (c != '\\')
            *out++ = c; // regular, unescaped character
        else
        {                   // escaped character; process it...
            c = *in++;
            if      (c == '0') *out++ = '\0';
            else if (c == 'a') *out++ = '\a';
            else if (c == 'b') *out++ = '\b';
            else if (c == 'f') *out++ = '\f';
            else if (c == 'n') *out++ = '\n';
            else if (c == 'r') *out++ = '\r';
            else if (c == 't') *out++ = '\t';
            else if (c == 'v') *out++ = '\v';
            else if (c == 'x'  // arbitrary hexadecimal value
                    && isxdigit(in[0]) && isxdigit(in[1]))
            {
                char x[3];
                x[0] = *in++;
                x[1] = *in++;
                x[3] = '\0';
                *out++ = strtol(x, NULL, 16);
            }
            else if (c>='0' && c<='3' // arbitrary octal value
                    && in[0]>='0' && in[0]<='7'
                    && in[1]>='0' && in[1]<='7')
            {
                *out++ = (c-'0')*64 + (in[0]-'0')*8 + (in[1]-'0');
                in += 2;
            }
            else // any other char following '\' is just itself.
                *out++ = *in++;
        }
        ++len; // each time through the loop adds one character
    }
    *out = '\0';
    return len;
}

