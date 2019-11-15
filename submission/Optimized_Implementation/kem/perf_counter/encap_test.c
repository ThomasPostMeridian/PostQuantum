//encap_test.c


#define _GNU_SOURCE

#include "api.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>


uint8_t* hexstr_to_char_2(const char* hexstr, int32_t *size);

int comp_ss(unsigned char* ss_a, unsigned char * ss_b){
	for(int i = 0; i < CRYPTO_BYTES; i++){
		if(ss_a[i] != ss_b[i]){
			return 0;
		}
	}
	return 1;
}


int main()
{
	int keys_to_test = 1;
	unsigned char *pk; 
	unsigned char ss_tx[keys_to_test][CRYPTO_BYTES];
	unsigned char ct[keys_to_test][CRYPTO_CIPHERTEXTBYTES];
	int return_code = 0;
	FILE *key_file;

	// Open file with public key
	if ( (key_file = fopen("test_keys1.txt", "r")) == NULL ) {
	fprintf(stderr, "Couldn't open <test_keys> for write\n");
		return -1;
	}

	// read public key
	char * line = NULL;
	size_t ignore = 0;
	ssize_t key_len = 0;

	key_len = getline(&line, &ignore, key_file);
	if( key_len/2 != CRYPTO_PUBLICKEYBYTES){
		fprintf(stderr, "Key file size error: read: %i expected %i\n", (int) key_len/2, CRYPTO_PUBLICKEYBYTES);
		return -1;
	}
	int32_t key_read_size; 

	//printf("Reading in public key\n");// of length %i %c %i\n", (int) key_len, line[key_len-2], line[key_len-2]);
	line[key_len-1] = 0;
	// convert public key
	pk = hexstr_to_char_2(line, &key_read_size);
	if(pk == NULL){
		fprintf(stderr, "Null key error\n");
		return -1;
	}
	
	if(key_read_size != CRYPTO_PUBLICKEYBYTES){
		fprintf(stderr, "Key conversion size error: read %i expected %i\n", key_read_size, CRYPTO_PUBLICKEYBYTES);
		return -1;
	}


	fclose(key_file);
	if (line){
		free(line);	
	}


	
	// run the encapsulation fuction
	for(int i = 0; i < keys_to_test; i++){	
		return_code = crypto_kem_enc(ct[i], ss_tx[i], pk);
		if(return_code != 0){
			fprintf(stderr, "Encap failed with code: %i\n", return_code);
		}
/*
		return_code = crypto_kem_dec(ss_rx[i], ct[i], sk[i]);
		if(return_code != 0){
			fprintf(stderr, "Key gen failed with code: %i\n", return_code);
		}
*/

	}
	printf("Run successful\n");
	return 0;

}





uint8_t* hexstr_to_char_2(const char* hexstr, int32_t *size)
{
    int i, j;
    uint8_t* buffer = NULL;
    size_t len = strlen(hexstr);

    *size = 0;
    if (len & 1)
        return NULL;
    len >>= 1;

    if (!(buffer = (unsigned char*)malloc((len+1) * sizeof(uint8_t))))
        return NULL;

    for (i=0, j=0; j<len; i+=2, j++)
        buffer[j] = ((((hexstr[i] & 31) + 9) % 25) << 4) + ((hexstr[i+1] & 31) + 9) % 25;
    buffer[len] = '\0';
    *size = (int32_t)len;

    return buffer;
}

