/*
     This a a little server application.
     telnet <ESP-IP address> 8080
     and a "Hello World" packet will be sent back to you
*/

//ezPanda IP address is 83.212.106.103
//listens to port 10000

//#include <iostream>
//using namespace std;

using namespace std;
#include <iostream>
#include <string>

extern "C" {
     void app_main();
}
     #include <inttypes.h> //for printing uint16_t , ... , etc

     #include "freertos/FreeRTOS.h"
     #include "freertos/queue.h"
     #include "freertos/task.h"
     #include "freertos/event_groups.h"

     #include "driver/timer.h"

     #include "nvs_flash.h" //for nvs_flash_init();

     #include <esp_event.h>
     #include <esp_event_loop.h>
     #include <esp_wifi.h>
     #include <esp_err.h> //for the ESP_ERROR_CHECK()

     //for connecting to an AP
     #include <tcpip_adapter.h>
     #include <esp_system.h>

     #include "esp_types.h"
     #include "soc/timer_group_struct.h"
     #include "driver/periph_ctrl.h"

     #include <lwip/sockets.h>
     #include <lwip/netdb.h> //e.g. freeaddrinfo() ...

//     void IRAM_ATTR timerHandler(void *para);
//     static void tg0_timer_init(int timer_idx, bool auto_reload, double timer_interval_sec);
//     esp_err_t wifi_event_handler(void *ctx, system_event_t *event);
//     static void internet_app(void *arg);
//     void app_main();

#define TIMER_DIVIDER 16 //Hardware timer clock TIMER_DIVIDER
#define TIMER_SCALE (TIMER_BASE_CLK / TIMER_DIVIDER) //the frequency I will be having in my Timer. TIMER_BASE_CLK is normally 80MHz
#define TIMER_LED (5.0) //every 5 sec blibk make led=!led
#define TEST_WITH_RELOAD 1

#define GPIO_BLINKY_LED GPIO_NUM_5
static bool LED_STATE;

#define WIFI_SSID CONFIG_ESP_SSID_toConnect
#define WIFI_PASSWORD CONFIG_ESP_WIFI_PASSWORD

#define MAXDATASIZE 100

#define BACKLOG 4 //how many pending connections queue will hold
#define PORT_ACCEPT "8765" //the port users will be connecting to

static EventGroupHandle_t wifi_event_group; //to handle and sychronize wifi events
const int CONNECTED_BIT = BIT0; //when this bit is set, esp32 is connected to a wifi LAN network

/*
//handling TCP packets for now
class Server
{
     private:
          struct addrinfo *server_info;
          int socket_listen = NULL;

          Server();
          ~Server();
          void createSocket(); //creates, binds, listens to a socket
          string void wait4Request();
          void writeResponse();
          void closeClientSocket();
};

class Client
{
     protected: host = null;

     protected: void createSocket(); //creates socket and binds to the server
};
*/


void IRAM_ATTR timerHandler(void *para)
{
     int timer_idx = (int) para;

     //uint32_t intr_status = TIMERG0.int_st_timers.val; //retrieve interrupt status
     TIMERG0.hw_timer[timer_idx].update = 1;

     //Clear the interrupt & Update the alarm time for the timer which has auro_reload cleared
     //we use reload so :
     TIMERG0.int_clr_timers.t0 = 1;

     //We must enable again the alarm, if we want to get triggered again.
     TIMERG0.hw_timer[timer_idx].config.alarm_en = TIMER_ALARM_EN;
     //printf("Invert led !\n" );
     LED_STATE = !LED_STATE;
     gpio_set_level(GPIO_BLINKY_LED, LED_STATE);
}


static void tg0_timer_init(timer_idx_t timer_idx, bool auto_reload, double timer_interval_sec)
{
     //initialize basic parameters of the timer_idx
     timer_config_t config; //data structure with timer's configuration settings
     config.divider = TIMER_DIVIDER; //the divider's range is from 2 to 65536
     config.counter_dir = TIMER_COUNT_UP;
     config.counter_en = TIMER_PAUSE; //don't start counting
     config.alarm_en = TIMER_ALARM_EN; //enable alarm
     config.intr_type = TIMER_INTR_LEVEL; //alarm will be level based (no max-enabled) //MAYBE ERROR
     config.auto_reload = auto_reload; //when alarm happens, what will the counter become?
     timer_init(TIMER_GROUP_0, timer_idx, &config);

     // Timer's counter will initially start from value below.
     // Also, if auto_reload is set, this value will be automatically reload on alarm
     timer_set_counter_value(TIMER_GROUP_0, timer_idx, 0x00000000ULL); //Unsigned Long Long

     timer_set_alarm_value(TIMER_GROUP_0, timer_idx, timer_interval_sec*TIMER_SCALE); //set the level of the alarm
     timer_enable_intr(TIMER_GROUP_0, timer_idx);
     timer_isr_register(TIMER_GROUP_0, timer_idx, timerHandler, (void *)timer_idx,
          ESP_INTR_FLAG_IRAM, NULL); //maybe modify this ?

     timer_start(TIMER_GROUP_0, timer_idx);
}

esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
     switch(event->event_id)
     {
          case SYSTEM_EVENT_SCAN_DONE:
          {
               uint16_t apCount = event->event_info.scan_done.number;
               printf("###|Number of access points found : %" PRIu16 "\n", apCount);
               if (apCount == 0)
                    return ESP_OK;
               wifi_ap_record_t *list = (wifi_ap_record_t *) malloc (sizeof(wifi_ap_record_t) * apCount);
               ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&apCount, list)); //also frees the WIFI driver dynamic allocated memory (in which the returned values are stored)
               //apCount pass to tell how many to give me. and returns by telling me how many it actually gave me
               for (int i = 0; i<apCount ; i++)
               {
                    std::string authmode;
                    switch(list[i].authmode)
                    {
                         case WIFI_AUTH_OPEN:
                              authmode = "WIFI_AUTH_OPEN";
                              break;
                         case WIFI_AUTH_WEP:
                              authmode = "WIFI_AUTH_WEP";
                              break;
                         case WIFI_AUTH_WPA_PSK:
                              authmode = "WIFI_AUTH_WPA_PSK";
                              break;
                         case WIFI_AUTH_WPA2_PSK:
                              authmode = "WIFI_AUTH_WPA2_PSK";
                              break;
                         case WIFI_AUTH_WPA_WPA2_PSK:
                              authmode = "WIFI_AUTH_WPA_WPA2_PSK";
                              break;
                         default:
                              authmode = "Unknown";
                    }
                    cout <<"###|ssid = " <<list[i].ssid <<"rssi = " << static_cast<int>(list[i].rssi) <<", authmode = " <<authmode <<endl;
               }
               free(list);
               printf("###|Connecting to a LAN network . . .\n");
               ESP_ERROR_CHECK(esp_wifi_connect());
               break;
          }case SYSTEM_EVENT_STA_GOT_IP:
          {
               //ip4_addr_t ipConnected;
               //ipConnected = event->event_info.got_ip.ip_info.ip ;
               //printf ("###|Our IP address is " IPSTR "\n", IP2STR(&ipConnected));
               //printf ("###|We are now connected to a Access Point.");
               xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
               break;
          }
          case SYSTEM_EVENT_STA_DISCONNECTED:
          {
               printf("###|Disconnected from wifi\n");
               xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
               break;
          }
          default:
               break;
     }
     return ESP_OK;
}


//get sockaddr, IPv4 or IPv6
//accepts sockaddr_storage as input only
void *get_in_addr(struct sockaddr *sa)
{
     if (sa->sa_family == AF_INET) //if it's IPv4
          return &(((struct sockaddr_in*)sa)->sin_addr);
     else //it's IPv6
          return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//called by xTaskCreate in main
static void internet_app(void *arg)
{
     tcpip_adapter_ip_info_t ip_info;
     ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info));
     printf("###|esp32 : IP Address  : %s\n", ip4addr_ntoa(&ip_info.ip));
     printf("###|esp32 : Subnet Mask : %s\n", ip4addr_ntoa(&ip_info.netmask));
     printf("###|esp32 : Gateway     : %s\n", ip4addr_ntoa(&ip_info.gw));
     //server-side code
     int sock_listen = NULL, sock_new = NULL, numbytes;
     char buf[MAXDATASIZE];
     struct addrinfo hints, *servinfo, *p;
     struct sockaddr_storage their_addr; //connector's address information. IPv4 or IPv6
     socklen_t sin_size;
     char s[INET6_ADDRSTRLEN];
     int rv;

     memset(&hints, 0, sizeof(hints));
     hints.ai_family = AF_UNSPEC; //use either IPv4 or IPv6
     hints.ai_socktype = SOCK_STREAM; //TCP packets
     hints.ai_flags = AI_PASSIVE; //use my IP, since I am a server

     if ( (rv = getaddrinfo(NULL, PORT_ACCEPT, &hints, &servinfo)) == 0 )
     {
          //loop through all the results and bind to the first we can
          for (p=servinfo ; p != NULL ; p=p->ai_next)
          {
               if ( (sock_listen = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
               {
                    printf("###|No luck in socket...\n");
                    continue;
               }
               //if (setsockopt) // manipulate options for the socket
               if (bind(sock_listen, p->ai_addr, p->ai_addrlen))
               {
                    printf("###|No luck in bind...\n");
                    close(sock_listen);
                    continue;
               }
               //print bind settings
               void* addr;
               string ipver;
               // get the pointer to the address itself,
               // different fields in IPv4 and IPv6:
               if (p->ai_family == AF_INET) // IPv4
               {
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                    addr = &(ipv4->sin_addr);
                    ipver = "IPv4";
               } else // IPv6
               {
                    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                    addr = &(ipv6->sin6_addr);
                    ipver = "IPv6";
               }
               // convert the IP to a string and print it:
               inet_ntop(p->ai_family, addr, s, sizeof(s));
               //printf("###|Server binded to --> %s: %s  port %s\n", ipver, s, PORT_ACCEPT);
               cout <<"###|Server binded to --> " <<ipver <<": " <<s  <<"port " <<PORT_ACCEPT <<endl;
               break;
          }
          freeaddrinfo(servinfo); //all done with this structure.
          if (p != NULL)
          {
                    if (listen(sock_listen, BACKLOG) != -1)
                    {
                         printf("###|Server listening . . .\n");
                         while(true) //main accept() loop
                         {
                              sin_size = sizeof(their_addr);
                              sock_new = accept(sock_listen, (struct sockaddr *)&their_addr, &sin_size);
                              if (sock_new == -1)
                              {
                                   perror("###|Cannot accept\n");
                                   close(sock_new);
                                   continue;
                              }
                              inet_ntop(their_addr.ss_family, //convert IP customer addreess to printable
                                   get_in_addr((struct sockaddr*)&their_addr ), s, sizeof(s));
                              printf("###|SERVER : got connection from %s\n", s);

                              if ((numbytes = recv(sock_new, buf, MAXDATASIZE-1, 0)) == -1) //returns the number of bytes read
                              {
                                   perror("###|Cannot recv\n");
                                   close(sock_new);
                                   continue;
                              }
                              buf[numbytes] = '\0';
                              char response[2*MAXDATASIZE] = "You said :";
                              strcat(response, buf);
                              if (send(sock_new, response, strlen(response)+1, 0) == -1)
                              {
                                   perror("send");
                                   close(sock_new);
                                   continue;
                              }
                              close(sock_new);
                         }
                    }else
                         perror("###|Cannot listen\n");
          }else
               perror("###|socket_listen is NULL\n");
     }else
          perror("###|Cannot getaddrinfo\n");
     while(1)
     {
          vTaskDelay(10 / portTICK_PERIOD_MS);
     }
}

void app_main()
{
     //call blinky !
     printf("###|ezPanda ! \n");
     //make a blinky !
     gpio_set_direction(GPIO_BLINKY_LED, GPIO_MODE_OUTPUT);
     LED_STATE = 0;
     gpio_set_level(GPIO_BLINKY_LED, LED_STATE);
     tg0_timer_init(TIMER_0, TEST_WITH_RELOAD, TIMER_LED);
     //   3)given that we have an architecture of 4 byte stack width (one word),
     // the xTaskCreate reserves 2048*4 = 8072bytes = 8kB
     //   5)Priorities can be assigned
     // from 0, which is the lowest priority, to (configMAX_PRIORITIES – 1), which
     // is the highest priority
     ////xTaskCreate(timer_example_evt_task, "timer_evt_task", 2048, NULL, 5, NULL);

     //create an event group to handle wifi events and sychronize with app_main
     wifi_event_group = xEventGroupCreate();

     //continue to main program
     nvs_flash_init();
     tcpip_adapter_init();
     ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL)); //handler for wifi events
     wifi_init_config_t cgf = WIFI_INIT_CONFIG_DEFAULT(); //create object for initialization of wifi
     ESP_ERROR_CHECK(esp_wifi_init(&cgf)); //initialize wifi
     ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM)); //default value is FLASH.
     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA)); //make esp32 a station. not a Access Point

     wifi_scan_config_t scanConf = {}; //scan configurating
     //initialize
     scanConf.ssid = NULL;
     scanConf.bssid = NULL;
     scanConf.channel = 0;
     scanConf.show_hidden = 1;

     wifi_config_t sta_config = {}; //station configuration
     strcpy((char*)sta_config.sta.ssid, WIFI_SSID);
     strcpy((char*)sta_config.sta.password, WIFI_PASSWORD);
     sta_config.sta.bssid_set = 0;
     /*
     wifi_scan_config_t scanConf = //scan configurating
     {
          .ssid = NULL,
          .bssid = NULL,
          .channel = 0,
          .show_hidden = 1
     };

     wifi_config_t sta_config = //station configuration
     {
          .sta =
          {
               .ssid = WIFI_SSID,
               .password = WIFI_PASSWORD,
               .bssid_set = 0
          }
     };*/

     ESP_ERROR_CHECK(esp_wifi_set_auto_connect(false)); //disable auto connect
     ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
     ESP_ERROR_CHECK(esp_wifi_start()); //start wifi, according to current configuration
     ESP_ERROR_CHECK(esp_wifi_scan_start(&scanConf, 0)); //blocking (true) or non blocking (false) mode by the second parameter

     //wait indefinetely untill esp32 to connected
     xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
     xTaskCreate(internet_app, "connected_to_wifi_program", 2048, NULL, 5, NULL);
}
