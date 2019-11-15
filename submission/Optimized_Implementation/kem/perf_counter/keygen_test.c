// keygen_test.c


#include "api.h"
#include <stdio.h>
#include <unistd.h>



void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

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
	FILE *key_file;
	char key_file_name[20];



	int keys_to_test = 5;
	unsigned char pk[keys_to_test][CRYPTO_PUBLICKEYBYTES]; 
	unsigned char sk[keys_to_test][CRYPTO_SECRETKEYBYTES];
	unsigned char ss_tx[keys_to_test][CRYPTO_BYTES];
	unsigned char ss_rx[keys_to_test][CRYPTO_BYTES];
	unsigned char ct[keys_to_test][CRYPTO_CIPHERTEXTBYTES];
	int return_code = 0;
	
	for(int i = 0; i < keys_to_test; i++){	
		sprintf(key_file_name, "test_keys%i.txt", i);	
		printf("Writing keys to %s\n", key_file_name);

		if ( (key_file = fopen(key_file_name, "w")) == NULL ) {
		fprintf(stderr, "Couldn't open <%s> for write\n", key_file_name);
			return -1;
		}
		return_code = crypto_kem_keypair(pk[i], sk[i]);
		if(return_code != 0){
			fprintf(stderr, "Key gen failed with code: %i\n", return_code);
		}	
		fprintBstr(key_file, "", pk[i], CRYPTO_PUBLICKEYBYTES);
		fprintBstr(key_file, "", sk[i], CRYPTO_SECRETKEYBYTES);
		return_code = crypto_kem_enc(ct[i], ss_tx[i], pk[i]);
		if(return_code != 0){
			fprintf(stderr, "Key gen failed with code: %i\n", return_code);
		}
		return_code = crypto_kem_dec(ss_rx[i], ct[i], sk[i]);
		if(return_code != 0){
			fprintf(stderr, "Key gen failed with code: %i\n", return_code);
		}


		if(!comp_ss(ss_tx[i], ss_rx[i])){
			printf("SS doesn't match\n");
		}
		else{
			printf("Test successful\n");
		}
		//close(key_file);
	}

	return 0;

}


void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
        unsigned long long  i;

        fprintf(fp, "%s", S);

        for ( i=0; i<L; i++ )
                fprintf(fp, "%02X", A[i]);

        if ( L == 0 )
                fprintf(fp, "00");

        fprintf(fp, "\n");
}




