#include "rsa_enc_dec.h"
#include "aes_enc_dec.h"
#include <wifi_provisioning/wifi_config.h>
#define USER_ID_SZ 10
#define HOME_ID_SZ 10
#define AES_ENC_TYPE 256
#define CLOUD_RAND_SZ (AES_ENC_TYPE/8)
#define MOB_SYM_KEY_SZ (AES_ENC_TYPE/8)
#define MQTT_PREFIX_SZ 60
#define IV_SZ 16 //AES128, AES256 uses IV=16


typedef enum {
 FACTO_ONBOARDED,
 USER_ONBOARDED,
 UART_CONNECTED,
 WIFI_CONNECTED,
 CLOUD_CONNECTED,
 SLEEP,
 ERROR
}devstate_e;

typedef struct security
{
    aes_t   aes_ctx;
    enc_cloud_pk_t   cloud_pub_ctx;
    dec_dev_pk_t     dev_priv_ctx;
}security_t;

typedef struct mqqt{
    char mqtt_topics_prefix[MQTT_PREFIX_SZ];//yet to decide
    char userId[USER_ID_SZ];// userId
    char homeId[HOME_ID_SZ];// homeId
}mqqt_info_t;


//upon successful onboard wifi and mqqtt credentials will be stored in flash
 typedef struct onbording_s
 {
    unsigned   char mob_sym_key[MOB_SYM_KEY_SZ]; //16 bytes only
    unsigned char iv[IV_SZ]; // initialization-vector,
    unsigned char cloud_rand[CLOUD_RAND_SZ];//: <cloud-random-number>
 }onboard_t;

typedef struct device
{
    devstate_e e_state;
    mqqt_info_t t_mqtt;
    wifi_prov_config_set_data_t    t_wifi;
    security_t tsec;
    onboard_t *pt_onb;
}dev_info_t;