/*  WiFi softAP Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <sys/param.h>

#include "device_info.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <wifi_provisioning/wifi_config.h>
#include "lwip/err.h"
#include "lwip/sys.h"

#include "lwip/sockets.h"
#include <lwip/netdb.h>
#include "cJSON.h"
#define CONFIG_EXAMPLE_IPV4
/* The examples use WiFi configuration that you can set via 'make menuconfig"'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_MAX_STA_CONN       CONFIG_MAX_STA_CONN

#define PORT CONFIG_EXAMPLE_PORT
/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

static const char *TAG = "UOB_MOB2DEV";

// static esp_err_t event_handler(void *ctx, system_event_t *event)
// {
//     switch(event->event_id) {
//     case SYSTEM_EVENT_AP_STACONNECTED:
//         ESP_LOGI(TAG, "station:"MACSTR" join, AID=%d",
//                  MAC2STR(event->event_info.sta_connected.mac),
//                  event->event_info.sta_connected.aid);
//         break;
//     case SYSTEM_EVENT_AP_STADISCONNECTED:
//         ESP_LOGI(TAG, "station:"MACSTR"leave, AID=%d",
//                  MAC2STR(event->event_info.sta_disconnected.mac),
//                  event->event_info.sta_disconnected.aid);
//         break;
//     default:
//         break;
//     }
//     return ESP_OK;
// }

// void wifi_init_softap()
// {
//     s_wifi_event_group = xEventGroupCreate();

//     tcpip_adapter_init();
//     ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

//     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//     ESP_ERROR_CHECK(esp_wifi_init(&cfg));
//     wifi_config_t wifi_config = {
//         .ap = {
//             .ssid = EXAMPLE_ESP_WIFI_SSID,
//             .ssid_len = strlen(EXAMPLE_ESP_WIFI_SSID),
//             .password = EXAMPLE_ESP_WIFI_PASS,
//             .max_connection = EXAMPLE_MAX_STA_CONN,
//             .authmode = WIFI_AUTH_OPEN
//         },
//     };
//     if (strlen(EXAMPLE_ESP_WIFI_PASS) == 0) {
//         wifi_config.ap.authmode = WIFI_AUTH_OPEN;
//     }

//     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
//     ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
//     ESP_ERROR_CHECK(esp_wifi_start());

//     ESP_LOGI(TAG, "wifi_init_softap finished.SSID:%s password:%s",
//              EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
// }
///shiva


int hex2data(unsigned char *data,  unsigned char *hexstring, unsigned int len)
{
    unsigned char *pos = hexstring;
    char *endptr;
    size_t count = 0;

    //ESP_LOGI(TAG,"hex2data  %d \n", );

    if ((hexstring[0] == '\0')||((size_t)(strlen((char *)hexstring))%2 )) {
        //hexstring contains no data
        //or hexstring has an odd length
        ESP_LOGE(TAG,"hex2data failed \n");

        return -1;
    }


    for(count = 0; count < len; count++) {
        char buf[5] = {'0', 'x', pos[0], pos[1], 0};


        data[count] = strtol(buf, &endptr, 0);


        pos += 2 * sizeof(char);

        if (endptr[0] != '\0') {
            //non-hexadecimal character encountered
            return -1;
        }
    }
    data[count]=0;

    return 0;
}

#define BREAK_ON_FAIL(state) { if(state<0) break; }
typedef enum {
	INT=1,
	CHAR,
    SHORT,
	OPEN_SIZE_MAX4K
}ctype_e;

typedef union buff{
	int ibuff;
	char cbuff[4096];
}buff_u;
typedef struct process_buff{
	buff_u b;
	int size;
	ctype_e type;
}pbuff_t;

int uob_mob2dev_getdata(int sock, pbuff_t *pt_buff){
   			char *pbuf=NULL;
            switch(pt_buff->type){
                case INT:
                case SHORT:
   	            	pbuf=(char *)&pt_buff->b.ibuff;
   	                break;
                case CHAR:
   	        	    pbuf=&pt_buff->b.cbuff[0];
                    break;
                default:
                	break;
            }

            int len = recv(sock, pbuf, pt_buff->size, 0);
            // Error occured during receiving
            if (len < 0) {
                ESP_LOGE(TAG, "recv failed: errno %d", errno);
                return -1;
            }
            // Connection closed
            else if (len == 0) {
                ESP_LOGI(TAG, "Connection closed");
                return -1;
            }
            // Data received
            else {
            	if(pt_buff->type==INT){
                    int stream_len=ntohl(pt_buff->b.ibuff);
                    ESP_LOGI(TAG, "LEN %x", stream_len);
                    pt_buff->b.ibuff = stream_len;
            	}else{
            		pt_buff->b.cbuff[len]=0;
            		ESP_LOGI(TAG, "DATA %s", pt_buff->b.cbuff);
            	}
                //get data specified by stream_len
                //state=process_buffer(rx_buffer);
                int err = send(sock,"OK" , 2, 0);
                if (err < 0) {
                    ESP_LOGE(TAG, "Error occured during sending: errno %d", errno);
                    return -2;
                }
            	ESP_LOGI(TAG, "SEND OK") ;

            }
            return len;
}
#if 1
int  uob_mob2dev_parse_aes( char *aes_buffer,dev_info_t *pt_dev){
    const cJSON *    BSSID;// <mac-id>
    const cJSON * randomnumber;//: <cloud-random-number>
    const cJSON *  wifissid;//: wifiUserId
    const cJSON *  wifipassword;//: wifiPasswd
    const cJSON *  userId;// userId
    const cJSON * homeId;//: homeId
    cJSON *json = cJSON_Parse(aes_buffer);
    int status = 1;

    char *string = NULL;
    ESP_LOGI(TAG,"Parsing AES");
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            ESP_LOGE(TAG, "Error before: %d\n", errno);

        }
        goto end;
    }
    //cJSON_Print(json);
    string = cJSON_Print(json);
    if (string == NULL) {
        fprintf(stderr, "Failed to print monitor.\n");
    }
    ESP_LOGI(TAG,"string %s\n",string);

    BSSID = cJSON_GetObjectItemCaseSensitive(json, "BSSID");
    if (!(cJSON_IsString(BSSID) && (BSSID->valuestring != NULL)))
    {
        goto end;
    }

    randomnumber = cJSON_GetObjectItemCaseSensitive(json, "randomnumber");
    if(! (cJSON_IsString(randomnumber) && (randomnumber->valuestring != NULL)))
    {
        goto end;
    }
    wifissid = cJSON_GetObjectItemCaseSensitive(json, "wifissid");
    if(! (cJSON_IsString(wifissid) && (wifissid->valuestring != NULL)))
    {
        goto end;
    }

    wifipassword = cJSON_GetObjectItemCaseSensitive(json, "wifipassword");
    if(! (cJSON_IsString(wifipassword) && (wifipassword->valuestring != NULL)))
    {
        goto end;
    }

    userId = cJSON_GetObjectItemCaseSensitive(json, "userId");
    if (!(cJSON_IsString(userId) && (userId->valuestring != NULL)))
    {
        goto end;

    }
    homeId = cJSON_GetObjectItemCaseSensitive(json, "homeId");
    if (!(cJSON_IsString(homeId) && (homeId->valuestring != NULL)))
    {
        goto end;

    }
    ////
    #if 0
    typedef struct {
        char    ssid[33];       /*!< SSID of the AP to which the slave is to be connected */
        char    password[65];   /*!< Password of the AP */
        char    bssid[6];       /*!< BSSID of the AP */
        uint8_t channel;        /*!< Channel of the AP */
    } wifi_prov_config_set_data_t;

    #endif
    /**WIFI DETAILS */
    ESP_LOGI(TAG," BSSID \"%s\"\n", BSSID->valuestring);
    memcpy(pt_dev->t_wifi.bssid,BSSID->valuestring,6);

    ESP_LOGI(TAG," wifissid \"%s\"\n", wifissid->valuestring);
    memcpy(pt_dev->t_wifi.ssid, wifissid->valuestring,strlen(wifissid->valuestring));

    ESP_LOGI(TAG," wifipassword \"%s\"\n", wifipassword->valuestring);
    memcpy(pt_dev->t_wifi.password, wifipassword->valuestring,strlen(wifipassword->valuestring));

    /** DEV LOCATION */
    ESP_LOGI(TAG," userId \"%s\"\n", userId->valuestring);
    memcpy(pt_dev->t_mqtt.userId,userId->valuestring,strlen(userId->valuestring));

    ESP_LOGI(TAG," homeId \"%s\"\n", homeId->valuestring);
    memcpy(pt_dev->t_mqtt.homeId,homeId->valuestring,strlen(homeId->valuestring));

    ESP_LOGI(TAG," randomnumber \"%s\"\n", randomnumber->valuestring);
    memcpy(pt_dev->pt_onb->cloud_rand, randomnumber->valuestring,CLOUD_RAND_SZ);

    
    set_config_handler(const wifi_prov_config_set_data_t *req_data, wifi_prov_ctx_t **ctx)

    status=0;
end:
    cJSON_Delete(json);
    return;


}
#endif


int uob_mob2dev_decrypt(unsigned char *key, unsigned char *iv,unsigned char *payload,size_t payload_len, dev_info_t *pt_dev){
    size_t olen;//=MOB_SYM_KEY_SZ;
    int ret=1;
    if(dev_rsa_priv_key_int(&pt_dev->tsec.dev_priv_ctx,NULL)){
        ESP_LOGE(TAG,"dev_rsa_priv_key_int failed \n");

         return 1;
    }
        ESP_LOGI(TAG,"uob_mob2dev_decrypt \n");

    olen=MOB_SYM_KEY_SZ;
    size_t ilen=128;
    ESP_LOGI(TAG,"RSA key len \"%d\"\n", ilen);

    if(dev_rsa_decrypt(&pt_dev->tsec.dev_priv_ctx,key,ilen,pt_dev->pt_onb->mob_sym_key,&olen))    {
        ESP_LOGE(TAG,"dev_rsa_decrypt key failed \n");
        return 1;
    }

    olen = IV_SZ;
    ilen =128;
    //ilen  = 128
    ESP_LOGI(TAG,"iv key len \"%d\"\n", ilen);

    if(dev_rsa_decrypt(&pt_dev->tsec.dev_priv_ctx,iv,ilen,pt_dev->pt_onb->iv,&olen)){
        ESP_LOGE(TAG,"dev_rsa_decrypt IV  failed \n");

        return 1;
    }

    ESP_LOGI(TAG,"pt_dev->pt_onb->mob_sym_key ");//\"%s\"\n", pt_dev->pt_onb->mob_sym_key);
    ESP_LOGI(TAG,"pt_dev->pt_onb->iv");// \"%s\"\n", pt_dev->pt_onb->iv);

    //fill aes context.
    aes_t *aes_ctx=&pt_dev->tsec.aes_ctx;
    memcpy(aes_ctx->key ,pt_dev->pt_onb->mob_sym_key,MOB_SYM_KEY_SZ);
    aes_ctx->keylen = MOB_SYM_KEY_SZ;
    memcpy(aes_ctx->IV,pt_dev->pt_onb->iv,IV_SZ);

    aes_ctx->mode=MODE_DECRYPT;
    aes_ctx->enc_buffer = payload;
    aes_ctx->enc_len = payload_len;
    aes_ctx->plain_buffer = payload;
    aes_ctx->plain_len = payload_len;
    if (aes_enc_dec(aes_ctx)){
        ESP_LOGE(TAG,"aes_enc_dec   failed \n");

        return 1;
    }

    ESP_LOGI(TAG,"plain_buffer \"%s\"\n", aes_ctx->plain_buffer);
    uob_mob2dev_parse_aes((char *)aes_ctx->plain_buffer,pt_dev);
    return 0;

}

int uob_mob2dev_parse(pbuff_t *pb,dev_info_t *pt_dev){
    cJSON *json = cJSON_Parse(pb->b.cbuff);
    const cJSON *key = NULL;
    const cJSON *iv = NULL;
    const cJSON *payload = NULL;
    int status = 1;
    char *string = NULL;
    ESP_LOGI(TAG,"Parsing");
    //cJSON_Print(json);
    string = cJSON_Print(json);
    if (string == NULL) {
        fprintf(stderr, "Failed to print monitor.\n");
    }
    ESP_LOGI(TAG,"string %s\n",string);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            ESP_LOGE(TAG, "Error before: %d\n", errno);

        }
        goto end;
    }
#if 0 //for pkt understanding.
       key: EN(device-pub-key){symmetric-key},
       iv: initialization-vector,
       payload: EN(symmetric-key){
       BSSID: <mac-id>
       randomnumber: <cloud-random-number>
       wifissid: wifiUserId
       wifipassword: wifiPasswd
       userId: userId
       homeId: homeId
#endif
    //key=cJSON_GetObjectItem(json,"key");
    key = cJSON_GetObjectItemCaseSensitive(json, "key");
    if (!(cJSON_IsString(key) && (key->valuestring != NULL)))
    {
        goto end;
    }

    iv = cJSON_GetObjectItemCaseSensitive(json, "iv");
    if(! (cJSON_IsString(iv) && (iv->valuestring != NULL)))
    {
        goto end;
    }

    payload = cJSON_GetObjectItemCaseSensitive(json, "payload");
    if (!(cJSON_IsString(payload) && (payload->valuestring != NULL)))
    {
        goto end;

    }


    ESP_LOGI(TAG,"Checking key \"%s\"\n", key->valuestring);
    ESP_LOGI(TAG,"Checking iv \"%s\"\n", iv->valuestring);
    ESP_LOGI(TAG,"Checking payload \"%s\"\n", payload->valuestring);
    if(hex2data((unsigned char*)key->valuestring,(unsigned char*)key->valuestring,128)){
        ESP_LOGE(TAG, "hex2data key : %d\n", errno);
        goto end;
    }

    // for(int i=0;i<128;i++)
    //     mbedtls_printf("%x", key->valuestring[i]);
    // mbedtls_printf("\n");//>valuestring[i]);


    if(hex2data((unsigned char*)iv->valuestring,(unsigned char*)iv->valuestring,128))
    {
        ESP_LOGE(TAG, "hex2data iv : %d\n", errno);
        goto end;

    }

    size_t payload_len=(size_t)(strlen(payload->valuestring)/2);
    if(hex2data((unsigned char *)payload->valuestring,(unsigned char*)payload->valuestring,payload_len))
    {
        ESP_LOGE(TAG, "hex2data payload : %d\n", errno);
        goto end;

    }
    mbedtls_printf("payload len=%d \n", payload_len );//>valuestring[i]);
    if( !uob_mob2dev_decrypt((unsigned char *)key->valuestring,(unsigned char *)iv->valuestring,(unsigned char *)payload->valuestring,payload_len,pt_dev))
        goto end;

    status = 0;
end:
    cJSON_Delete(json);
    return status;

}

//dev_info_t t_dev;

static void tcp_server_task(void *pt_dev)
{
    char addr_str[128];
    int addr_family;
    int ip_protocol;

    while (1) {

#ifdef CONFIG_EXAMPLE_IPV4
        struct sockaddr_in destAddr;
        destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(PORT);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;
        inet_ntoa_r(destAddr.sin_addr, addr_str, sizeof(addr_str) - 1);
#else // IPV6
        struct sockaddr_in6 destAddr;
        bzero(&destAddr.sin6_addr.un, sizeof(destAddr.sin6_addr.un));
        destAddr.sin6_family = AF_INET6;
        destAddr.sin6_port = htons(PORT);
        addr_family = AF_INET6;
        ip_protocol = IPPROTO_IPV6;
        inet6_ntoa_r(destAddr.sin6_addr, addr_str, sizeof(addr_str) - 1);
#endif

        int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
        if (listen_sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket created");

        int err = bind(listen_sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
        if (err != 0) {
            ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket binded");
		while(1){
			err = listen(listen_sock, 1);
			if (err != 0) {
				ESP_LOGE(TAG, "Error occured during listen: errno %d", errno);
				break;
			}
			ESP_LOGI(TAG, "Socket listening");

			struct sockaddr_in6 sourceAddr; // Large enough for both IPv4 or IPv6
			uint addrLen = sizeof(sourceAddr);
			int sock = accept(listen_sock, (struct sockaddr *)&sourceAddr, &addrLen);
			if (sock < 0) {
				ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
				break;
			}
			ESP_LOGI(TAG, "Socket accepted");
			// Get the sender's ip address as string
			if (sourceAddr.sin6_family == PF_INET) {
				inet_ntoa_r(((struct sockaddr_in *)&sourceAddr)->sin_addr.s_addr, addr_str, sizeof(addr_str) - 1);
			} else if (sourceAddr.sin6_family == PF_INET6) {
				inet6_ntoa_r(sourceAddr.sin6_addr, addr_str, sizeof(addr_str) - 1);
			}
			pbuff_t *pb=NULL;
			pb=malloc(sizeof(pbuff_t));
			if(pb==NULL){
				ESP_LOGE(TAG, "unable to allocate memory %d", errno);
				break;
			}

			while (1) {
				//get length
				int state;

				//read length
				pb->type=INT;
				pb->size=4;
				state= uob_mob2dev_getdata(sock,pb);
				BREAK_ON_FAIL(state);

				//read JSON data
				pb->size = pb->b.ibuff;
				pb->type=CHAR;
				state=uob_mob2dev_getdata(sock,pb);
				BREAK_ON_FAIL(state);

                uob_mob2dev_parse(pb,(dev_info_t*)pt_dev);
			}
			if(pb!=NULL){
				ESP_LOGI(TAG, "Freeing allocate memory");
				free(pb);
			}
			if (sock != -1) {
				ESP_LOGE(TAG, "Shutting down socket and restarting...");
				shutdown(sock, 0);
				close(sock);
			}
		 }
    }
    vTaskDelete(NULL);
}

#if 0
security_t tsec;
void test_crpyto(void){
    int eret;
    size_t olen;
       eret=dev_rsa_pub_key_init( &tsec.dev_priv_ctx);
    if(eret ==0){
        olen=1024;
        dev_rsa_encrypt(&tsec.dev_priv_ctx,(unsigned char *)"shiva test",(size_t)11, tsec.dev_priv_ctx.buf,&olen);
    }
    eret=dev_rsa_priv_key_int( &tsec.dev_priv_ctx,NULL);
    if(eret ==0){
        int ilen=olen;
        olen=100;

        dev_rsa_decrypt(&tsec.dev_priv_ctx,tsec.dev_priv_ctx.buf,ilen,tsec.dev_priv_ctx.buf,&olen);
    }

    aes_t *aes_ctx=&tsec.aes_ctx;
    memcpy(aes_ctx->key ,"12345678ABCDABDC",16);
    aes_ctx->keylen = 16;
    for(int i =0;i< 4096;i++){
        aes_ctx->plain_buffer[i]= i%256;
        //mbedtls_printf("%d ",(int)aes_ctx->plain_buffer[i]&0xff);

    }
    ESP_LOGI(TAG, "AES_BUFF_INFLATED");
   aes_ctx->plain_len=4096;
   memset(aes_ctx->IV,1,16);
   aes_ctx->mode=MODE_ENCRYPT;
   ESP_LOGI(TAG, "AES_ENC_CALLED");
    eret=aes_enc_dec(aes_ctx);
    if(eret==0){
         ESP_LOGI(TAG, "AES_ENC_COMPLEATE");
        aes_ctx->mode=MODE_DECRYPT;
        eret=aes_enc_dec(aes_ctx);
                 ESP_LOGI(TAG, "AES_DEC_COMPLEATE");

        if(eret==0){
              for(int i =0;i< 4096;i++)
              {
                    if(aes_ctx->plain_buffer[i]!= i%256){
                            ESP_LOGE(TAG, " %d ",aes_ctx->plain_buffer[i]);
                    }
              }
        }
    }

}
#endif

//dev_info_t t_dev;
//onboard_t t_onb;
onboard_t* uob_mob2dev_new(){
    onboard_t *ob;

    ob = (onboard_t *) calloc(1, sizeof(onboard_t));
    if (!ob) {
       ESP_LOGE(TAG, "Error allocating onboarding buffer");
       return NULL;
    }


    return ob;
}

int uob_mob2dev_delete(onboard_t* ob){
    if (!ob) {
       ESP_LOGE(TAG, "Error allocating onboarding buffer");
       return 1;
    }
    free(ob);
    return 0;

}

void uob_mob2dev_start(dev_info_t *pt_dev)
{

   return xTaskCreate(tcp_server_task, "Onb_tcp_server", (4096*2), pt_dev, 5,  &pt_dev->pt_onb->task_handle);
}


void uob_mob2dev_stop(dev_info_t *pt_dev)
{
    if( pt_dev->pt_onb->task_handle != NULL )
     {
        vTaskDelete( xHandle );
     }
     if(pt_dev->pt_onb!=NULL){

        free(pt_dev->pt_onb);
    }

}
