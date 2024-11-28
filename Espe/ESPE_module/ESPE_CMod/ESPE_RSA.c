#include<Python.h>
#include<stdlib.h>
#include<openssl/aes.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#define AES_BLOCK_SIZE 16
#define AES_DATA_SIZE 163840
#define RSA_DATA_SIZE 3072
#define KB512 524288
unsigned char test_AES_encrypt_data[KB512];
unsigned long int test_AES_sample , test_AES_size;
unsigned char test_RSA_encrypt_data[RSA_DATA_SIZE];
unsigned char test_AES_key[RSA_DATA_SIZE];
// aes len recommend 256
int my_rsa_readkey(char *path_key , unsigned char* p_rsa)
{
	FILE *file = NULL;
	int  rsa_len = 0; 

	if((file = fopen(path_key, "r")) == NULL)
	{
	    printf("%s\n", "error in openfile");
	}
	char c;        
	while((c=fgetc(file))!=EOF)
	{
		p_rsa[rsa_len] = c;
		rsa_len++;
	}
	rsa_len--;
	fclose(file);
	return rsa_len;
}
int my_rsa_encrypt(unsigned char *from ,unsigned char *to, char *path_key)
{
	RSA  *p_rsa = NULL;
	FILE *file = NULL;
	char *p_en = NULL;
	int  rsa_len = 0;

	unsigned char str[RSA_DATA_SIZE];
	memset(str , 0 , RSA_DATA_SIZE);
	memcpy(str+8, from , AES_BLOCK_SIZE);

	if((file = fopen(path_key, "rb")) == NULL)
	{
	    goto End;
	}        
	
	if((p_rsa = PEM_read_RSA_PUBKEY(file, NULL,NULL,NULL )) == NULL)
	{
		perror("PEM_read_RSA_PUBKEY()");
	    goto End;
	}
	
	rsa_len = RSA_size(p_rsa);

	p_en = (unsigned char *)malloc(rsa_len+1);
    
	memset(p_en, 0, rsa_len+1);
	int p_en_len;
	if((p_en_len = RSA_public_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_NO_PADDING))< 0)
	{
	    perror("RSA_public_encrypt()");
	    goto End;
	}

	End:

	if(p_rsa)    RSA_free(p_rsa);
	if(file)     fclose(file);

	memcpy( to ,p_en , p_en_len);
	return p_en_len;
 }   
int my_rsa_decrypt(unsigned char *str ,unsigned char* b_de ,char *path_key)
{
	RSA  *p_rsa = NULL;
	FILE *file = NULL;
	int   rsa_len = 0;
	char *p_de = NULL;

	file = fopen(path_key, "rb");
	if(!file)
	{
	    goto End;
	}        

	if((p_rsa = PEM_read_RSAPrivateKey(file, NULL,NULL,NULL )) == NULL)
	{
	    perror("PEM_read_RSAPrivateKey()");
	    goto End;
	}

	rsa_len = RSA_size(p_rsa);

	p_de = (char *)malloc(rsa_len + 1);

	memset(p_de, 0, rsa_len + 1);

	int p_de_len;
	if((p_de_len = RSA_private_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING)) < 0)
	{
	    perror("RSA_private_decrypt()");
	    goto End;
	}
	End:        

	if(p_rsa)    RSA_free(p_rsa);
	if(file)     fclose(file);
	memcpy( b_de ,p_de+8 , rsa_len);
	return p_de_len;
}  
int my_aes_encrypt(unsigned char *in , unsigned char *out , size_t len , unsigned char* key)
{

	if(!in||!key||!out)
	{
		printf("%s\n" , "invaid input");
		return -1;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv , 0 , AES_BLOCK_SIZE);

	AES_KEY aes;

	if(AES_set_encrypt_key((unsigned char*)key , 128 , &aes) < 0)
	{
		perror("AES_set_encrypt_key()");
		return 0;
	}

	AES_cbc_encrypt((unsigned char*)in , (unsigned char*)out , len , &aes , iv , AES_ENCRYPT);

	return len;
}
int my_aes_decrypt(unsigned char *in , unsigned char *out , size_t len  , unsigned char* key)
{
	if(!in||!key||!out)
	{

		return -1;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv , 0 , AES_BLOCK_SIZE);

	AES_KEY aes;
	if(AES_set_decrypt_key((unsigned char*)key , 128 , &aes) < 0)
	{
		perror("AES_set_decrypt_key()");
		return 0;
	}
	AES_cbc_encrypt((unsigned char*)in , (unsigned char*)out , len , &aes , iv , AES_DECRYPT);

	return len;
}
static PyObject* IoT_Encryption(PyObject *self , PyObject *args)
{
	PyObject * ret;
	unsigned char *RSA_keypath , * plain_text;
	unsigned char AES_key[AES_BLOCK_SIZE+1];
	unsigned char RSA_public_key[RSA_DATA_SIZE];
	unsigned char RSA_encrypt_data[RSA_DATA_SIZE];
	unsigned char AES_encrypt_data[AES_DATA_SIZE];
	int RSA_public_key_length , RSA_encrypt_data_length , AES_encrypt_data_length;

	if(!PyArg_ParseTuple(args , "ss" , &plain_text , &RSA_keypath))
  	{
      return NULL;
  	}

  	RAND_pseudo_bytes(AES_key,AES_BLOCK_SIZE);
  	AES_key[AES_BLOCK_SIZE] = 0;

  	RSA_public_key_length	= my_rsa_readkey(RSA_keypath,RSA_public_key);
	RSA_encrypt_data_length	= my_rsa_encrypt(AES_key,RSA_encrypt_data,RSA_keypath);
	AES_encrypt_data_length	= my_aes_encrypt(plain_text , AES_encrypt_data ,AES_DATA_SIZE, AES_key);	
	
	ret = (PyObject *)Py_BuildValue("iy#iy#iy#",RSA_public_key_length,RSA_public_key,RSA_public_key_length
											   ,RSA_encrypt_data_length,RSA_encrypt_data,RSA_encrypt_data_length
											   ,AES_encrypt_data_length,AES_encrypt_data,AES_encrypt_data_length);
	return ret;
}
static PyObject* Manager_select(PyObject *self , PyObject *args)
{
	PyObject * ret;
	unsigned char RSA_public_key[RSA_DATA_SIZE];
	unsigned char* RSA_keypath;
	unsigned int RSA_public_key_length;
	if(!PyArg_ParseTuple(args , "s" , &RSA_keypath))
  	{
      return NULL;
  	}
	RSA_public_key_length	= my_rsa_readkey(RSA_keypath,RSA_public_key);
	ret = (PyObject *)Py_BuildValue("iy#",RSA_public_key_length,RSA_public_key,RSA_public_key_length);

	return ret;
	
}
static PyObject* Manager_decryption(PyObject *self , PyObject *args)
{
	PyObject * ret;
	unsigned char* RSA_public_key , * RSA_encrypt_data , * AES_encrypt_data , * RSA_keypath;
	unsigned int *RSA_public_key_length  , *AES_encrypt_data_length ,*RSA_encrypt_data_length;
	unsigned char  AES_key[RSA_DATA_SIZE];
	unsigned char plain_text[AES_DATA_SIZE];

	int  RSA_decrypt_data_length , AES_decrypt_data_length;
	if(!PyArg_ParseTuple(args , "y#y#y#s" , &RSA_public_key ,&RSA_public_key_length, &RSA_encrypt_data ,&RSA_encrypt_data_length, &AES_encrypt_data , &AES_encrypt_data_length,&RSA_keypath))
  	{
      return NULL;
  	}
  	//RSA_public_key_length_manager = RSA_readkey(RSA_keypath,RSA_public_key);
	RSA_decrypt_data_length	= my_rsa_decrypt(RSA_encrypt_data,AES_key,RSA_keypath);
	AES_decrypt_data_length	= my_aes_decrypt(AES_encrypt_data, plain_text ,AES_DATA_SIZE, AES_key);	
	
	ret = (PyObject *)Py_BuildValue("iy#iy#",AES_BLOCK_SIZE,AES_key,AES_BLOCK_SIZE
											,AES_decrypt_data_length,plain_text,AES_decrypt_data_length);
	return ret;	
}
static PyObject* decryption_test_init(PyObject *self , PyObject *args)
{
	PyObject * ret;
	unsigned int sample,aes_size;
	unsigned char * RSA_keypath;
	unsigned int PK_len;
	unsigned char RSA_public_key[RSA_DATA_SIZE];
	if(!PyArg_ParseTuple(args , "iis" , &sample ,&aes_size ,  &RSA_keypath))
  	{
      return NULL;
  	}

  	test_AES_sample = sample;
  	test_AES_size = aes_size;

  	memset(test_AES_encrypt_data , 0 , test_AES_size);
  	memset(test_AES_key , 'a' ,AES_BLOCK_SIZE);
  	test_AES_key[AES_BLOCK_SIZE] = 0;
  	PK_len = my_rsa_readkey(RSA_keypath,RSA_public_key);
  	my_rsa_encrypt(test_AES_key,test_RSA_encrypt_data,RSA_keypath);

  	ret = (PyObject *)Py_BuildValue("l" , test_AES_sample*((test_AES_size+RSA_DATA_SIZE+PK_len)/1024));

  	return ret;

}
static PyObject* decryption_test(PyObject *self , PyObject *args)
{
	PyObject * ret;
	unsigned char * RSA_keypath;
	unsigned int sample;
	if(!PyArg_ParseTuple(args , "s" ,&RSA_keypath))
  	{
      return NULL;
  	}
  	for(int i = 0 ; i < test_AES_sample ; i++)
  	{
  		my_rsa_decrypt(test_RSA_encrypt_data,test_AES_key,RSA_keypath);
  		my_aes_decrypt(test_AES_encrypt_data,test_AES_encrypt_data, test_AES_size, test_AES_key);	
  	}

  	ret = (PyObject *)Py_BuildValue("i" , sample);

  	return ret;
}
//general get a lib
static PyMethodDef
ESPE_methods[] = {
    {"IoTEncrypt" , IoT_Encryption, METH_VARARGS},
    {"ManaSelect" , Manager_select , METH_VARARGS},
    {"ManaDecrypt" , Manager_decryption , METH_VARARGS},
    {"TestInit" , decryption_test_init, METH_VARARGS},
    {"Testde" , decryption_test,METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
ESPE_mod = {
    PyModuleDef_HEAD_INIT,
    "ESPE_mod",
    "",
    -1,
    ESPE_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_ESPE_mod(void)
{
    return PyModule_Create(&ESPE_mod);
}