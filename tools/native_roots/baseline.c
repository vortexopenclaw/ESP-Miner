#include "sdk_bundle.c"
static int traced(void *ctx,mbedtls_x509_crt *crt,int depth,uint32_t *flags){uint32_t before=*flags;int ret=esp_crt_verify_callback(ctx,crt,depth,flags);printf("callback depth=%d incoming=0x%x outgoing=0x%x return=%d\\n",depth,before,*flags,ret);return ret;}
int main(int argc,char **argv){
 if(argc!=4)return 4;
 psa_crypto_init();
 FILE *f=fopen(argv[1],"rb");if(!f)return 4;
 fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);unsigned char *b=malloc(n);if(!b)return 4;fread(b,1,n,f);fclose(f);
 mbedtls_x509_crt peer;mbedtls_x509_crt_init(&peer);
 mbedtls_ssl_config conf;mbedtls_ssl_config_init(&conf);
 int r=mbedtls_ssl_config_defaults(&conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);
 if(!r)r=esp_crt_bundle_set(b,n);if(!r)r=esp_crt_bundle_attach(&conf);
 if(!r)r=mbedtls_x509_crt_parse_file(&peer,argv[2]);
 uint32_t flags=0;
 if(!r)r=mbedtls_x509_crt_verify(&peer,conf.MBEDTLS_PRIVATE(ca_chain),NULL,argv[3],&flags,conf.MBEDTLS_PRIVATE(f_vrfy)==esp_crt_verify_callback?traced:conf.MBEDTLS_PRIVATE(f_vrfy),conf.MBEDTLS_PRIVATE(p_vrfy));
 printf("verify_return=%d flags=0x%x\n",r,flags);
 mbedtls_x509_crt_free(&peer);mbedtls_ssl_config_free(&conf);free(b);mbedtls_psa_crypto_free();return r?2:0;
}
