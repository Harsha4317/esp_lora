
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_wifi.h"
#include "protocol_examples_common.h"
#include "lwip/sockets.h"
#include <esp_https_server.h>
#include "sdkconfig.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_server.h"
#include "esp_wifi_types.h"
#include "esp_tls.h"

#define AP_SSID      "creeperX"
#define AP_PASSWORD  "Linear*20"
int global_variable ;

#define FILE_NAME_BUFFER_SIZE 256
char Client_Certificate [500];
char Root_Certificate [500];
char Client_Private_Key [500];


char mac_addr_string[18];
static char Device_Address[50] = "3A7F9B2C";
static char Application_Session_Key[50] = "3A7F9B2C1D5E8F0A3A7F9B2C1D5E8F0A";
static char Network_Session_Key[50] = "3A7F9B2C1D5E8F0A3A7F9B2C1D5E8F0A";
static char Unique_End_Device_Address[50] = "3A7F9B2C1D5E8F0A";
static char Unique_Application_Identifier[50] = "3A7F9B2C1D5E8F0A";
static char Application_Key[50] = "3A7F9B2C1D5E8F0A3A7F9B2C1D5E8F0B";

// Hardcoded login credentials
#define VALID_USERNAME "admin"
#define VALID_PASSWORD "password"

static const char *TAG = "https_server";
static const size_t max_clients = 4;

static httpd_handle_t start_https_server(void);

static esp_err_t stop_https_server(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_ssl_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        if (stop_https_server(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop https server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        *server = start_https_server();
    }
}
//////////***********connection handlers********///////////////


/////////////////////***** An HTTP GET handler for the login page **********//////////////

static esp_err_t login_get_handler(httpd_req_t *req)
{
    extern const unsigned char index_html_start[] asm("_binary_index_html_start");
    //extern const unsigned char index_html_end[] asm("_binary_index_html_end");
    const char *html_data = (const char *)index_html_start;

    ESP_LOGI(TAG, "GET: Sending response");
    httpd_resp_send(req, html_data, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/////////////////////////////////******* configure_ap_get_handler *******///////////////////////////

static esp_err_t configure_ap_get_handler(httpd_req_t *req)
{
    if (global_variable==0) {
                    // Redirect to login page if the user is not logged in
                    httpd_resp_set_status(req, "302 Found");
                    httpd_resp_set_hdr(req, "Location","/");
                    httpd_resp_send(req, NULL, 0);
                        }
    extern const unsigned char login_html_start[] asm("_binary_login_html_start");
    //extern const unsigned char login_html_end[] asm("_binary_login_html_end");
    const char *login_html_data = (const char *)login_html_start;
    ESP_LOGI(TAG, "GET: Sending response");
    httpd_resp_send(req, login_html_data, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/////////////////////////////////******* lora_get_handler*** with dynamic html text *******/////////////////////

static esp_err_t lora_get_handler(httpd_req_t *req) {
    // Check if the user is logged in
    if (global_variable == 0) {
        // Redirect to the login page if the user is not logged in
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }
    extern const unsigned char lora_html_start[] asm("_binary_lora_html_start");
    extern const unsigned char lora_html_end[] asm("_binary_lora_html_end");
    size_t lora_html_len = lora_html_end - lora_html_start;
    const char *lora_html_data = (const char *)lora_html_start;
    const char *placeholders[] = {
        "%MAC_ADDRESS_VALUE%",
         "%DEV_ADDR_8bit_Device_Address%",
          "%APPsKEY_32bit_Application_Session_Key%",
           "%NWKSKEY_32bit_Network_Session_Key%",
            "%DEVEUI_16bit_Unique_End_Device_Address%",
             "%APPEUI_16bit_Unique_Application_Identifier%",
              "%APPKEY_32bit_Application_Key%",
    };

    // Corresponding replacement values
    const char *replacement_values[] = {
        mac_addr_string,
         Device_Address,
          Application_Session_Key,
           Network_Session_Key,
            Unique_End_Device_Address,
             Unique_Application_Identifier,
              Application_Key
    };

    // Loop through placeholders
    for (int i = 0; i < sizeof(placeholders) / sizeof(placeholders[0]); i++) {
        const char *pos = strstr(lora_html_data, placeholders[i]);

        // Check if the placeholder was found
        if (pos != NULL) {
            size_t placeholder_len = strlen(placeholders[i]);
            size_t first_part_len = pos - lora_html_data;
            httpd_resp_send_chunk(req, lora_html_data, first_part_len);
            httpd_resp_send_chunk(req, replacement_values[i], strlen(replacement_values[i]));
            lora_html_data = pos + placeholder_len;
        } else {
            ESP_LOGE(TAG, "Placeholder not found: %s", placeholders[i]);
        }
    }
    httpd_resp_send_chunk(req, lora_html_data, lora_html_len - (lora_html_data - (const char *)lora_html_start));
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}



int i;
/////////////////////////////////////*** wifi get handler for handling wifi config ***/////////////////////

static esp_err_t wifi_get_handler(httpd_req_t *req)
{
extern const uint8_t _binary_wifi_config_html_start[] asm("_binary_wifi_config_html_start");
 extern const uint8_t _binary_wifi_config_html_end[] asm("_binary_wifi_config_html_end");
  size_t lora_html_len = _binary_wifi_config_html_end - _binary_wifi_config_html_start;
   const char *lora_html_data1 = (const char *)_binary_wifi_config_html_start;
    const char *placeholder1 = "%Unique_ID%";
     char *pos = strstr(lora_html_data1, placeholder1);
      size_t placeholder_len = strlen(placeholder1);
       size_t first_part_len = pos - lora_html_data1;
        httpd_resp_send_chunk(req, lora_html_data1, first_part_len);
if (strlen(mac_addr_string) >= placeholder_len)
{

httpd_resp_send_chunk(req, mac_addr_string, strlen(mac_addr_string));
size_t remaining_len = lora_html_len - (pos - lora_html_data1) - placeholder_len;
httpd_resp_send_chunk(req, pos + placeholder_len, remaining_len);
}
else
{
ESP_LOGE(TAG, "Not enough space for MAC address replacement");
}
httpd_resp_send_chunk(req, NULL, 0);
return ESP_OK;

}




esp_err_t wifi_post_handler(httpd_req_t *req) {
    char buf[3000];
    int ret, remaining = req->content_len;
    ESP_LOGI(TAG, "POST: Len %d", req->content_len);
    while (remaining > 0) {
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                // Retry receiving if timeout occurred
                continue;
            }
            return ESP_FAIL;
        }

        remaining -= ret;
        buf[ret] = '\0';
       //ESP_LOGI(TAG, "String after removing newlines:\n%s\n", buf);
        i++;
        ESP_LOGI(TAG, "String i value:%d\n", i);
         if(i == 2){
        
            strcpy(Client_Certificate, buf);
            ESP_LOGI(TAG, "String Client_Certificate value:%s\n", Client_Certificate);
        }
        if(i == 4){
        
            strcpy(Root_Certificate, buf);
            ESP_LOGI(TAG, "String Root_Certificate value:%s\n", Root_Certificate);
        }
        if(i == 6){
        
            strcpy(Client_Private_Key, buf);
            ESP_LOGI(TAG, "String Client_Private_Key value:%s\n", Client_Private_Key);
        }
    }
    const char *success_resp = "<html><body><h1>Lora Configuration Successful!</h1></body></html>";
    httpd_resp_send(req, success_resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}



/////////////////////////////////////* An HTTP POST handler for handling login requests *////////////////////

static esp_err_t login_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    ESP_LOGI(TAG, "POST: Len %d", req->content_len);

    while (remaining > 0) {
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                // Retry receiving if timeout occurred
                continue;
            }
            return ESP_FAIL;
        }
        remaining -= ret;
        buf[ret] = '\0';  // Null-terminate the received data
        ESP_LOGI(TAG, "POST: Rx: %s", buf);

        char *username_start = strstr(buf, "username=");
        char *password_start = strstr(buf, "password=");

        if (username_start != NULL && password_start != NULL) {
            username_start += strlen("username=");
            password_start += strlen("password=");
            char username[50];
            char password[50];
            sscanf(username_start, "%49[^&]", username);
             sscanf(password_start, "%49s", password);
              
              ESP_LOGI(TAG, "username %s", username);
               ESP_LOGI(TAG, "password %s", password);

            // Check if credentials are valid
            if (strcmp(username, VALID_USERNAME) == 0 && strcmp(password, VALID_PASSWORD) == 0) {
                global_variable =1;
                  if (global_variable== 1) {
                    // Redirect to login page if the user is not logged in
                    httpd_resp_set_status(req, "302 Found");
                    httpd_resp_set_hdr(req, "Location","/configure_ap");
                    httpd_resp_send(req, NULL, 0);
                        }
                //const char *success_resp = "<html><body><h1>Login successful!</h1></body></html>";
                 // Send empty response body
            } else {
                httpd_resp_set_hdr(req, "Location", "/");
                    httpd_resp_set_status(req, "302 Found");
                    httpd_resp_send(req, NULL, 0);
                    return ESP_OK;
            }
        }
    }

    return ESP_OK;
}

///////////////////////////////////////////////configure_ap_post_handler//////////////////////////////

static esp_err_t configure_ap_post_handler(httpd_req_t *req) {
     
    char buf[100];
    int ret, remaining = req->content_len;

    ESP_LOGI(TAG, "POST: Len %d", req->content_len);

    while (remaining > 0) {
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                // Retry receiving if timeout occurred
                continue;
            }
            return ESP_FAIL;
        }
        remaining -= ret;
        buf[ret] = '\0';  // Null-terminate the received data
        ESP_LOGI(TAG, "POST: Rx: %s", buf);

        // Parse the received data (assuming a simple form with SSID and password fields)
        char *ssid_start = strstr(buf, "ssid=");
         char *password_start = strstr(buf, "password=");

        if (ssid_start != NULL && password_start != NULL) {
            // Move the pointers to the actual values
            ssid_start += strlen("ssid");
             password_start += strlen("password");

            // Extract SSID and password
            char ssid[50];
             char password[50];
              sscanf(ssid_start, "=%49[^&]", ssid);
               sscanf(password_start, "=%49s", password);
                ESP_LOGI(TAG, "SSID: %s", ssid);
                 ESP_LOGI(TAG, "Password: %s", password);

           if (global_variable==1) {
                    // Redirect to login page if the user is not logged in
                    httpd_resp_set_status(req, "302 Found");
                     httpd_resp_set_hdr(req, "Location","/lora_config");
                      httpd_resp_send(req, NULL, 0);
                        }
            else{
            httpd_resp_set_status(req, "302 Found");
             httpd_resp_set_hdr(req, "Location","/");
              httpd_resp_send(req, NULL, 0); 
           // const char *success_resp = "<html><body><h1>Access Point configured successfully!</h1></body></html>";
            // httpd_resp_send(req1, success_resp, HTTPD_RESP_USE_STRLEN);
            }
        }
    }

    return ESP_OK;
}
//////////////////////**** wifi get handler *****//////////////////////////////////
static esp_err_t wifisetup_get_handler(httpd_req_t *req)
{
    extern const unsigned char wifisetup_html_start[] asm("_binary_wifisetup_html_start");
    extern const unsigned char login_html_end[] asm("_binary_wifisetup_html_end");
    const char *wifisetup_html_data = (const char *)wifisetup_html_start;
    ESP_LOGI(TAG, "GET: Sending response");
    httpd_resp_send(req, wifisetup_html_data, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}



/////////////////////******** wifi setup *******//////////////////////////////////////

static esp_err_t wifisetup_post_handler(httpd_req_t *req) {
     
    char buf[400];
    int ret, remaining = req->content_len;

    ESP_LOGI(TAG, "POST: Len %d", req->content_len);

    while (remaining > 0) {
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                // Retry receiving if timeout occurred
                continue;
            }
            return ESP_FAIL;
        }
        remaining -= ret;
        buf[ret] = '\0';  // Null-terminate the received data
        ESP_LOGI(TAG, "POST: Rx: %s", buf);

        // Parse the received data (assuming a simple form with SSID and password fields)
        char *ssid_start = strstr(buf, "SSID=");
         char *password_start = strstr(buf, "Password=");
          char *Unique_ID= strstr(buf, "Unique_ID=");
           char *Client_ID= strstr(buf, "Client_ID=");
            char *Broker_Url= strstr(buf, "Broker_Url=");
             char *Port_Number= strstr(buf, "Port_Number=");

        if (ssid_start != NULL && password_start != NULL) {
            // Move the pointers to the actual values
            ssid_start += strlen("SSID");
             password_start += strlen("Password");
              Unique_ID+=strlen("Unique_ID");
               Client_ID+=strlen("Client_ID");
                Broker_Url+=strlen("Broker_Url");
                 Port_Number+=strlen("Port_Number");

            // Extract SSID and password
            char ssid[50];
             char password[50];
              char Uniqueid[50];
               char Clientid[50];
                char Brokerid[50];
                 char Portnumber[50];

           sscanf(ssid_start, "=%49[^&]", ssid);
            sscanf(password_start, "=%49[^&]", password);
             sscanf(Unique_ID, "=%49[^&]", Uniqueid);
              sscanf(Client_ID, "=%49[^&]", Clientid);
               sscanf(Broker_Url, "=%49[^&]", Brokerid);
                sscanf(Port_Number, "=%49s", Portnumber);


            ESP_LOGI(TAG, "SSID: %s", ssid);
             ESP_LOGI(TAG, "Password: %s", password);
              ESP_LOGI(TAG, "Unique ID: %s", Uniqueid);
               ESP_LOGI(TAG, "Client ID: %s", Clientid);
                ESP_LOGI(TAG, "Broker Url: %s", Brokerid);
                 ESP_LOGI(TAG, "Port Number: %s", Portnumber);
           
            httpd_resp_set_status(req, "302 Found");
             httpd_resp_set_hdr(req, "Location","/wifi");
              httpd_resp_send(req, NULL, 0);

        }
    }

    return ESP_OK;
}
/////////////////////////////////// lora_post_handler_code //////////////////////////////


 static esp_err_t lora_post_handler(httpd_req_t *req) {
    if (global_variable == 0) {
        // Redirect to the login page if the user is not logged in
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char buf[250];
    int ret, remaining = req->content_len;

    ESP_LOGI(TAG, "POST: Len %d", req->content_len);

    while (remaining > 0) {
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                // Retry receiving if timeout occurred
                continue;
            }
            return ESP_FAIL;
        }

        remaining -= ret;
        buf[ret] = '\0';  // Null-terminate the received data
        ESP_LOGI(TAG, "POST: Rx: %s", buf);

        // Parse the received data (assuming a simple form with SSID and password fields)
        char *DeviceName = strstr(buf, "DeviceName=");
        char *ProvisioningMode = strstr(buf, "ProvisioningMode=");
        char *Application_Identifier = strstr(buf, "APPEUI=");
        char *End_Device_Address = strstr(buf, "DEVEUI=");
        char *Application_Key = strstr(buf, "APPKEY=");

        char *Device_Address = strstr(buf, "DEV_ADDR=");
        char *Application_Session_Key = strstr(buf, "APPsKEY=");
        char *Network_Session_Key = strstr(buf, "NWKSKEY=");

        if (DeviceName != NULL && ProvisioningMode != NULL) {
            // Move the pointers to the actual values
            DeviceName += strlen("DeviceName");
            ProvisioningMode += strlen("ProvisioningMode");
            Application_Identifier += strlen("APPEUI");
            End_Device_Address += strlen("DEVEUI");
            Application_Key += strlen("APPKEY");

            Device_Address += strlen("DEV_ADDR");
            Application_Session_Key += strlen("APPsKEY");
            Network_Session_Key += strlen("NWKSKEY");

            // Extract SSID and password
            char Device[50], Provisioning[50], APPEUI[50], DEVEUI[50], APPKEY[50], DEV_ADDR[50];
            char APPsKEY[50], NWKSKEY[50];
            sscanf(DeviceName, "=%49[^&]", Device);
            sscanf(ProvisioningMode, "=%49[^&]", Provisioning);
            
            char *ProvisioningMode1 = "OTAA";
            char *ProvisioningMode2 = "ABP";
            ESP_LOGI(TAG, "DeviceName: %s", Device);
            ESP_LOGI(TAG, "ProvisioningMode: %s", Provisioning);
            char *Provisioning1 = Provisioning;

            if (strstr(Provisioning1, ProvisioningMode1) != NULL) {
                sscanf(Application_Identifier, "=%49[^&]", APPEUI);
                sscanf(End_Device_Address, "=%49[^&]", DEVEUI);
                sscanf(Application_Key, "=%49[^&]", APPKEY);
                ESP_LOGI(TAG, "Application_Identifier: %s", APPEUI);
                ESP_LOGI(TAG, "End_Device_Address: %s", DEVEUI);
                ESP_LOGI(TAG, "Application_Key: %s", APPKEY);
            }
            if (strstr(Provisioning1, ProvisioningMode2) != NULL) {
                sscanf(Application_Identifier, "=%49[^&]", APPEUI);
                sscanf(End_Device_Address, "=%49[^&]", DEVEUI);
                sscanf(Application_Key, "=%49[^&]", APPKEY);
                sscanf(Device_Address, "=%50[^&]", DEV_ADDR);
                sscanf(Application_Session_Key, "=%49[^&]", APPsKEY);
                sscanf(Network_Session_Key, "=%49[^&]", NWKSKEY);
                ESP_LOGI(TAG, "Device_Address: %s", DEV_ADDR);
                ESP_LOGI(TAG, "Application_Session_Key: %s", APPsKEY);
                ESP_LOGI(TAG, "Network_Session_Key: %s", NWKSKEY);
            }

            const char *success_resp = "<html><body><h1>Lora Configuration Successful!</h1></body></html>";
            httpd_resp_send(req, success_resp, HTTPD_RESP_USE_STRLEN);
        }
    }

    return ESP_OK;
}
                  
//////////////////////////////******* server starting from hear ***********///////////

static httpd_handle_t start_https_server(void)
{
    // Start the httpd server
    httpd_handle_t server = NULL;
    ESP_LOGI(TAG, "Starting server");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.httpd.max_open_sockets = max_clients;

    extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
    extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
    conf.servercert = servercert_start;
    conf.servercert_len = servercert_end - servercert_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    conf.prvtkey_pem = prvtkey_pem_start;
    conf.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;

    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }

    ///////////////********* Set URI handlers*********//////////////////


    ESP_LOGI(TAG, "Registering URI handlers");
//login get handler //

                static const httpd_uri_t login_form = {
                    .uri       = "/",
                    .method    = HTTP_GET,
                    .handler   = login_get_handler,
                    .user_ctx  = NULL
                };              
    httpd_register_uri_handler(server, &login_form);

 // login post handler/// 

                    static const httpd_uri_t login_post = {
                        .uri       = "/enter",
                        .method    = HTTP_POST,
                        .handler   = login_handler,
                        .user_ctx  = NULL
                    };

        httpd_register_uri_handler(server, &login_post);

                        static const httpd_uri_t configure_ap_get = {
                            .uri       = "/configure_ap",
                            .method    = HTTP_GET,
                            .handler   = configure_ap_get_handler,
                            .user_ctx  = NULL
                        };
            httpd_register_uri_handler(server, &configure_ap_get);

                            static const httpd_uri_t configure_ap_post = {
                                .uri       = "/configure_ap1",
                                .method    = HTTP_POST,
                                .handler   = configure_ap_post_handler,
                                .user_ctx  = NULL
                            };
                httpd_register_uri_handler(server, &configure_ap_post);


                                       static const httpd_uri_t lora_get_config = {
                                    .uri       = "/lora_config",
                                    .method    = HTTP_GET,
                                    .handler   = lora_get_handler,
                                    .user_ctx  = NULL
                                };
                    httpd_register_uri_handler(server, &lora_get_config);
                                    static const httpd_uri_t lora_post_config = {
                                        .uri       = "/lora_config1",
                                        .method    = HTTP_POST,
                                        .handler   = lora_post_handler,
                                        .user_ctx  = NULL
                                    };
                       httpd_register_uri_handler(server, &lora_post_config);

                                        static const httpd_uri_t wifi_get_config = {
                                            .uri       = "/wifi",
                                            .method    = HTTP_GET,
                                            .handler   = wifi_get_handler,
                                            .user_ctx  = NULL
                                        };
                            httpd_register_uri_handler(server, &wifi_get_config);


                                            static const httpd_uri_t wifi_post_config = {
                                                .uri       = "/wifipost",
                                                .method    = HTTP_POST,
                                                .handler   = wifi_post_handler,
                                                .user_ctx  = NULL
                                            };
                                 httpd_register_uri_handler(server, &wifi_post_config);
                                        
                                //             static const httpd_uri_t get_wifisetup = {
                                //                     .uri       = "/wifisetup/",
                                //                     .method    = HTTP_GET,
                                //                     .handler   = wifisetup_get_handler,
                                //                     .user_ctx  = NULL
                                //                 };
                                //     httpd_register_uri_handler(server, &get_wifisetup);

                                //                         static const httpd_uri_t post_wifisetup1 = {
                                //                         .uri       = "/wifiset",
                                //                         .method    = HTTP_POST,
                                //                         .handler   = wifisetup_post_handler,
                                //                         .user_ctx  = NULL
                                //                     };
                                //         httpd_register_uri_handler(server, &post_wifisetup1);
                                                   

                                             return server;
                }
             

///////////////********* main function **********///////////////////////

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
                                     

#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif 
    ESP_ERROR_CHECK(example_connect());
                                        uint8_t mac_addr[6];
                                        // Get the MAC address of the Wi-Fi STA interface
                                        esp_err_t err = esp_wifi_get_mac(ESP_IF_WIFI_STA, mac_addr);
                                        if (err != ESP_OK) {
                                            ESP_LOGE(TAG, "Failed to get MAC address: %s", esp_err_to_name(err));
                                            return;
                                        }
                                        // Print the MAC address
                                        ESP_LOGI(TAG, "MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                                                mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
                                        sprintf(mac_addr_string, "%02X:%02X:%02X:%02X:%02X:%02X",
                                              mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

                                            // Print the MAC address string
                                            ESP_LOGI(TAG, "MAC address: %s", mac_addr_string);
    // Wait indefinitely
    vTaskSuspend(NULL);
}
