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
#include <exception>

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

     #include <pthread.h>
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
#define GPIO_APACHE_LED GPIO_NUM_4
static bool LED_STATE;

#define WIFI_SSID CONFIG_ESP_SSID_toConnect
#define WIFI_PASSWORD CONFIG_ESP_WIFI_PASSWORD

#define MAXDATASIZE 100

#define BACKLOG 4 //how many pending connections queue will hold
#define PORT_ACCEPT "8765" //the port users will be connecting to
#define EZPANDA_IP "83.212.106.103"

static EventGroupHandle_t wifi_event_group; //to handle and sychronize wifi events
const int CONNECTED_BIT = BIT0; //when this bit is set, esp32 is connected to a wifi LAN network

//the Exception
class SocketException: public exception
{
     private:
          string msg;
          int ret;
          u32_t optlen;
     public:
          virtual const char* what() const throw()
          {
               return "###|Socket exception happened";
          } //0 error code means NO socket oriented error was made

          SocketException(int socket, string msgFromCode)
          {
               this->msg = msgFromCode;
               ret = 0;
               if (socket != 0)
               {
                    optlen = sizeof(ret);
                    getsockopt(socket, SOL_SOCKET, SO_ERROR, &ret, &optlen);
               }

               //convert ret-int to char*
               char retChars[3];
               sprintf(retChars, "%d", ret);

               //std::string stream ss <<"###|Error code " <<ret + <<": " <<msgFromCode;
               this->msg = "###|Error code " + std::string(retChars) + ": " + msgFromCode;
          }

          string getMsg()
          {
               return this->msg;
          }
};

//-----------------------------CLASS DECLARATTION START-----------------------------------//
class Connection
{
     protected:
          int socket_listen, socket_comm;
          //get sockaddr, IPv4 or IPv6
          //accepts sockaddr_storage as input only
          void *get_in_addr(struct sockaddr *sa)
          {
               if (sa->sa_family == AF_INET) //if it's IPv4
                    return &(((struct sockaddr_in*)sa)->sin_addr);
               else //it's IPv6
                    return &(((struct sockaddr_in6*)sa)->sin6_addr);
          }
     public:
          void closeClientSocket() { close(socket_comm); }
          void sendData(string response) //send
          {
               if (send(socket_comm, response.c_str(), response.length()+1, 0) == -1)
               {
                    SocketException e(socket_comm, "send() error");
                    throw e;
               }
          }
          string recvData() //recv
          {
               char buf[MAXDATASIZE];
               int numbytes;
               if ((numbytes = recv(socket_comm, buf, MAXDATASIZE-1, 0)) == -1) //returns the number of bytes read
               {
                    close(socket_comm);
                    SocketException e(socket_comm, "recv() error");
                    throw e;
               }
               buf[numbytes] = '\0';

               return std::string(buf);
          }
};

class Server: public Connection
{
     private:
          struct addrinfo hints, *server_info;
          const char *port_service;
          char IPaddress[INET6_ADDRSTRLEN];

     public:
          Server(string service);
          ~Server() { close(socket_listen); }
          void createSocket(); //creates, binds, listens to a socket
          string wait4ClientRequest(); //accepts, recv
};

// @arg 1 is port essentially
Server::Server(string service)
{
     socket_listen = 0;
     socket_comm = 0;
     port_service = service.c_str();

     memset(&hints, 0, sizeof(hints));
     hints.ai_family = AF_UNSPEC; //use either IPv4 or IPv6
     hints.ai_socktype = SOCK_STREAM; //TCP packets
     hints.ai_flags = AI_PASSIVE; //use my IP, since I am a server
}

void Server::createSocket()
{
     if (getaddrinfo(NULL, port_service, &hints, &server_info) != 0) //if fail
     {
          SocketException e(0, "getaddrinfo() error");
          throw e;
     }

     struct addrinfo *p;
     int count = 0;
     for (p=server_info ; p != NULL ; p=p->ai_next)
     {
          if ( (socket_listen = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
          {
               count++;
               continue;
          }
          if (bind(socket_listen, p->ai_addr, p->ai_addrlen))
          {
               count++;
               close(socket_listen);
               continue;
          }


          //---------------------------------- print bind settings ----------------------------------//
          void* addr;
          string ipver;
          //* get the pointer to the address itself,
          //* different fields in IPv4 and IPv6:
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

          //* convert the IP to a string and print it:
          inet_ntop(p->ai_family, addr, IPaddress, sizeof(IPaddress));
          cout <<"###|Server binded to --> " <<ipver <<": " <<IPaddress  <<"port " <<port_service <<endl;
          //-----------------------------------------------------------------------------------------//
          break;
     }
     if (p == NULL)
     {
          SocketException e(socket_listen, "socket_listen is NULL");
          throw e;
     }
     freeaddrinfo(server_info); //all done with this structure.
     if (listen(socket_listen, BACKLOG) == -1)
     {
          SocketException e(socket_listen, "listen() error");
          throw e;
     }
}

string Server::wait4ClientRequest()
{
     socklen_t sock_in_size;
     struct sockaddr_storage their_addr; //connector's address information. IPv4 or IPv6
     sock_in_size = sizeof(their_addr);

     if ((socket_comm = accept(socket_listen, (struct sockaddr *)&their_addr, &sock_in_size)) == -1)
     {
          close(socket_comm);
          SocketException e(socket_comm, "accept_error() error");
          throw e;
     }

     inet_ntop(their_addr.ss_family, //convert IP customer addreess to printable
          get_in_addr((struct sockaddr*)&their_addr ), IPaddress, sizeof(IPaddress));
     printf("###|SERVER : got connection from %s\n", IPaddress);

     //read request
     return recvData();
}

class Client: public Connection
{
     private:
          struct addrinfo hints, *server_info;
          const char *port_service;
          char IPaddress[INET6_ADDRSTRLEN];
     public:
          Client();
          ~Client() { close(socket_comm); }
          void createSocket(string serverName, string service);
};

Client::Client()
{
     socket_comm = 0;

     memset(&hints, 0, sizeof hints);
     hints.ai_family = AF_UNSPEC;
     hints.ai_socktype = SOCK_STREAM;
}

void Client::createSocket(string serverName, string service)
{
     port_service = service.c_str();

     if (getaddrinfo(serverName.c_str(), port_service, &hints, &server_info) != 0) //if fail
     {
          SocketException e(0, "getaddrinfo() client error");
          throw e;
     }

     struct addrinfo *p;
     int count = 0;
     for (p=server_info ; p != NULL ; p=p->ai_next)
     {
          if ( (socket_comm = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
          {
               count++;
               continue;
          }

          if (connect(socket_comm, p->ai_addr, p->ai_addrlen) == -1) {
               count++;
               close(socket_comm);
               continue;
          }
          break;
     }

     if (p == NULL)
     {
          SocketException e(socket_comm, "client failed to connect");
          throw e;
     }
     inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
          IPaddress, sizeof(IPaddress));
     printf("client: connecting to %s on port %s\n", IPaddress, port_service);

     freeaddrinfo(server_info); // all done with this structure
}

//---------------------CLASS DECLARATTION OVER---------------------------//

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
                    cout <<"###|ssid = " <<list[i].ssid <<" rssi = " << static_cast<int>(list[i].rssi) <<", authmode = " <<authmode <<endl;
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


//this function is run by the server thread
#define PORTB "4567" // backward connection
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void *servering(void *args)
{


     cout <<"###|Starting servering thread\n";
     string command, response="esp here reee !\n";

     //tdlt
     bool APACHE_LED_STATE = 0;
     gpio_set_direction(GPIO_APACHE_LED, GPIO_MODE_OUTPUT);
     gpio_set_level(GPIO_APACHE_LED, APACHE_LED_STATE);
     try
     {
          Client servableClient;
          servableClient.createSocket(EZPANDA_IP, "4567");

          while(1)
          {
               command = "";
               response = "";
               command = servableClient.recvData();
               cout <<"###|apache command :" <<command <<endl;

               //proccess command
               command = command.substr (0,command.length()-5);
               if (command.at(0) == '?')
               {
                    APACHE_LED_STATE = !APACHE_LED_STATE;
                    gpio_set_level(GPIO_APACHE_LED, APACHE_LED_STATE);
               }

               response = "ESP:" + command + "!\n";
               servableClient.sendData(response);
               cout <<"###|apache response :" <<response <<endl;

               //vTaskDelay(1000 / portTICK_PERIOD_MS);
          }
          servableClient.closeClientSocket();
     }catch (SocketException &e)
     {
          cout <<e.what() << e.getMsg() <<endl;
     }
     return NULL;
}

void app_main()
{
     //call blinky !
     printf("#########################################################\n");
     printf("#######################| ezPanda |#######################\n");
     printf("######################################################### \n");
     printf("╲╲╲╲◢◣▁▁▁▁▁◢◣╱╱╱╱\n");
     printf("╲╲╲╲◥▔▔▔▔▔▔▔◤╱╱╱╱\n");
     printf("╲╲╲╲▕▏▇▏┈▕▇▕▏╱╱╱╱\n");
     printf("╲╲╲╲▕▏◤┈▼┈◥▕▏╱╱╱╱\n");
     printf("╲╲╲╲▕▏╲╰━╯╱▕▏╱╱╱╱\n");
     printf("#########################################################\n");
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

     ESP_ERROR_CHECK(esp_wifi_set_auto_connect(false)); //disable auto connect
     ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
     ESP_ERROR_CHECK(esp_wifi_start()); //start wifi, according to current configuration
     ESP_ERROR_CHECK(esp_wifi_scan_start(&scanConf, 0)); //blocking (true) or non blocking (false) mode by the second parameter

     //wait indefinetely untill esp32 gets connected
     xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);

     //----------------------------INTERNET !---------------------------------//
     tcpip_adapter_ip_info_t ip_info;
     ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info));
     printf("###|esp32 : IP Address  : %s\n", ip4addr_ntoa(&ip_info.ip));
     printf("###|esp32 : Subnet Mask : %s\n", ip4addr_ntoa(&ip_info.netmask));
     printf("###|esp32 : Gateway     : %s\n", ip4addr_ntoa(&ip_info.gw));

     //creating pthread
     pthread_t server_thread;
     if (pthread_create(&server_thread, NULL, servering, NULL))
          printf("###|COULD NOT start server thread.\n");

     //server-side code
     /*
     try
     {
          Server server("9865");
          server.createSocket();
          while (true)
          {
               string request = server.wait4ClientRequest();
               string response = "You said :" + request;
               server.sendData(response);
               server.closeClientSocket();
          }
     }catch (SocketException &e)
     {
          cout <<e.what() << e.getMsg();
     }
     */

     //client-side code
     while(1)
     {
          try
          {
               Client client;
               client.createSocket(EZPANDA_IP, "5678");
               vTaskDelay(1500 / portTICK_PERIOD_MS);
               client.sendData("Light1:1\nLight2:0\nServo:1\nEnergyTransmitter:0!\n");
               string response = client.recvData();
               cout <<"###|" <<response <<endl;
               client.closeClientSocket();
          }catch (SocketException &e)
          {
               cout <<e.what() << e.getMsg() <<endl;
          }

          vTaskDelay(25000 / portTICK_PERIOD_MS);
     }

     /* wait for the server thread to finish */
     if(pthread_join(server_thread, NULL)) {
          printf("###|COULD NOT join server thread.\n");
          esp_restart();
     }
}
