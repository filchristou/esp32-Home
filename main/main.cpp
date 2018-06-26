//ezPanda IP address is 83.212.106.103
//listens to port 10000

//#include <iostream>
//using namespace std;

using namespace std;
#include <iostream>
#include <string>
#include <exception>
#include <unordered_map>

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
	#include "esp_log.h"

	//for connecting to an AP
	#include <tcpip_adapter.h>
	#include <esp_system.h>

	#include "esp_types.h"
	#include "soc/timer_group_struct.h"
	#include "driver/periph_ctrl.h"
	#include "driver/uart.h"
	#include "soc/uart_struct.h"

	#include <lwip/sockets.h>
	#include <lwip/netdb.h> //e.g. freeaddrinfo() ...

	//bluetooth libraries
	#include "esp_bt.h"
	#include "esp_bt_main.h"
	#include "esp_bt_device.h"
	#include "esp_gap_bt_api.h"

	#include "string.h"

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

#define GAP_TAG			"GAP"
#define USER_TAG		"USER_INFO"

#define CONNECTED_BIT 	(1 << 0) //when this bit is set, esp32 is connected to a wifi LAN network
#define BLUETOOTH_SCAN_BIT 	(1 << 1) //when this bit is set, esp32 has finished a bluetooth scan


#define TXD_PIN (GPIO_NUM_32)
#define RXD_PIN (GPIO_NUM_33)
#define QUEUE_TAG "QUEUE TAG"
//I am using UART1
static const int RX_BUF_SIZE = sizeof(char)*100;

//---freeRTOS Queue---//
QueueHandle_t uart_send_queue;
#define QUEUE_LENGTH 10
#define QUEUE_ITEM_SIZE sizeof(char)*100 //every message will have 100 chars maximum
//I am not useing a xQueue for receiving events, since I already got a RING BUFFER
// big enough to tolerate any delay.

pthread_mutex_t lockSocket; //to lock between bluetooth_send (main thread) & info_send (rx_thread)

//sensor data
//declaring variables
int ledsState[7];
/*
 * 0 --> Led Group Up
 * 1 --> Led Group Down
 * 2 --> Led Red
 * 3 --> Led Green
 * 4 --> RGB Led RED 
 * 5 --> RGB Led GREEN 
 * 6 --> RGB Led BLUE 
 */
float measurements[4];
/*
 * 0 --> temperature
 * 1 --> moisture
 * 2 --> Luminocity
 * 3 --> Distance
 */
bool doorState;

static EventGroupHandle_t xEventBits; //to handle and sychronize wifi events

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

//--------------------------------CLASS DECLARATTION START--------------------------------//
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


          //print bind settings
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


Client servableClient; //is accessed by many sections

//-------------------------------- TIMER --------------------------------//
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

//-------------------------------- WIFI --------------------------------//
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
               xEventGroupSetBits(xEventBits, CONNECTED_BIT);
               break;
          }
          case SYSTEM_EVENT_STA_DISCONNECTED:
          {
               printf("###|Disconnected from wifi\n");
               xEventGroupClearBits(xEventBits, CONNECTED_BIT);
               break;
          }
          default:
               break;
     }
     return ESP_OK;
}


//-------------------------------- WIFI-over --------------------------------//
//-------------------------------- BLUETOOTH --------------------------------//
std::unordered_map<std::string, std::string> bdaName_map;

typedef enum {
    APP_GAP_STATE_IDLE = 0,
    APP_GAP_STATE_DEVICE_DISCOVERING,
    APP_GAP_STATE_DEVICE_DISCOVER_COMPLETE,
    APP_GAP_STATE_SERVICE_DISCOVERING,
    APP_GAP_STATE_SERVICE_DISCOVER_COMPLETE,
} app_gap_state_t;

typedef struct {
    bool dev_found;
    uint8_t bdname_len;
    uint8_t eir_len;
    uint8_t rssi;
    uint32_t cod;
    uint8_t eir[ESP_BT_GAP_EIR_DATA_LEN];
    uint8_t bdname[ESP_BT_GAP_MAX_BDNAME_LEN + 1];
    esp_bd_addr_t bda;
    app_gap_state_t state;
} app_gap_cb_t;

static app_gap_cb_t m_dev_info;

static char *bda2str(esp_bd_addr_t bda, char *str, size_t size)
{
    if (bda == NULL || str == NULL || size < 18) {
        return NULL;
    }

    uint8_t *p = bda;
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            p[0], p[1], p[2], p[3], p[4], p[5]);
    return str;
}

static bool get_name_from_eir(uint8_t *eir, uint8_t *bdname, uint8_t *bdname_len)
{
    uint8_t *rmt_bdname = NULL;
    uint8_t rmt_bdname_len = 0;

    if (!eir) {
        return false;
    }

    rmt_bdname = esp_bt_gap_resolve_eir_data(eir, ESP_BT_EIR_TYPE_CMPL_LOCAL_NAME, &rmt_bdname_len);
    if (!rmt_bdname) {
        rmt_bdname = esp_bt_gap_resolve_eir_data(eir, ESP_BT_EIR_TYPE_SHORT_LOCAL_NAME, &rmt_bdname_len);
    }

    if (rmt_bdname) {
        if (rmt_bdname_len > ESP_BT_GAP_MAX_BDNAME_LEN) {
            rmt_bdname_len = ESP_BT_GAP_MAX_BDNAME_LEN;
        }

        if (bdname) {
            memcpy(bdname, rmt_bdname, rmt_bdname_len);
            bdname[rmt_bdname_len] = '\0';
        }
        if (bdname_len) {
            *bdname_len = rmt_bdname_len;
        }
        return true;
    }

    return false;
}

static void update_device_info(esp_bt_gap_cb_param_t *param)
{
    char bda_str[18];
    uint32_t cod = 0;
    int32_t rssi = -129; /* invalid value */
    esp_bt_gap_dev_prop_t *p;
	
	bda2str(param->disc_res.bda, bda_str, 18);
	//continue only if bda (Bluetooth Device Address is new)
	//bda_str carries the bda string. owo. 
	if (bdaName_map.count(std::string(bda_str)) <= 0) //if bda key doesn't exist
	{
		//store bda in a global variable, so that I can clean that when bt_device_scan is over
		//I need every scan to be independent and have no clue about the previous

		for (int i = 0; i < param->disc_res.num_prop; i++) {
			p = param->disc_res.prop + i;
			switch (p->type) {
			case ESP_BT_GAP_DEV_PROP_COD:
				cod = *(uint32_t *)(p->val);
				//ESP_LOGI(GAP_TAG, "--Class of Device: 0x%x", cod);
				break;
			case ESP_BT_GAP_DEV_PROP_RSSI:
				rssi = *(int8_t *)(p->val);
				//ESP_LOGI(GAP_TAG, "--RSSI: %d", rssi);
				break;
			case ESP_BT_GAP_DEV_PROP_BDNAME:
			default:
				break;
			}
		}

		/* search for device with MAJOR service class as "rendering" in COD (Class of Device) */
		app_gap_cb_t *p_dev = &m_dev_info;
		if (p_dev->dev_found && 0 != memcmp(param->disc_res.bda, p_dev->bda, ESP_BD_ADDR_LEN)) 
		{
			return;
		}

		//second condition: a device with Major device type "PHONE" in the Class of Device Field
		if (!esp_bt_gap_is_valid_cod(cod)) // ||
	//            !(esp_bt_gap_get_cod_major_dev(cod) == ESP_BT_COD_MAJOR_DEV_PHONE)) 
		{
			return;
		}

		memcpy(p_dev->bda, param->disc_res.bda, ESP_BD_ADDR_LEN);
		for (int i = 0; i < param->disc_res.num_prop; i++) {
			p = param->disc_res.prop + i;
			switch (p->type) {
			case ESP_BT_GAP_DEV_PROP_COD:
				p_dev->cod = *(uint32_t *)(p->val);
				break;
			case ESP_BT_GAP_DEV_PROP_RSSI:
				p_dev->rssi = *(int8_t *)(p->val);
				break;
			case ESP_BT_GAP_DEV_PROP_BDNAME: {
				uint8_t len = (p->len > ESP_BT_GAP_MAX_BDNAME_LEN) ? ESP_BT_GAP_MAX_BDNAME_LEN :
							  (uint8_t)p->len;
				memcpy(p_dev->bdname, (uint8_t *)(p->val), len);
				p_dev->bdname[len] = '\0';
				p_dev->bdname_len = len;
				break;
			}
			case ESP_BT_GAP_DEV_PROP_EIR: {
				memcpy(p_dev->eir, (uint8_t *)(p->val), p->len);
				p_dev->eir_len = p->len;
				break;
			}
			default:
				break;
			}
		}

		get_name_from_eir(p_dev->eir, p_dev->bdname, &p_dev->bdname_len);
		ESP_LOGI(GAP_TAG, "Device found: %s", bda2str(param->disc_res.bda, bda_str, 18));
		ESP_LOGI(GAP_TAG, "--Class of Device: 0x%x", cod);
		ESP_LOGI(GAP_TAG, "--RSSI: %d", rssi);
		ESP_LOGI(GAP_TAG, "Found a target device, address %s, name %s", bda_str, p_dev->bdname);
		//insert to unordered map
		bdaName_map.insert( {std::string(bda_str), std::string((char *)p_dev->bdname)} );
	}
}


void bt_app_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t *param)
{
    switch (event) { //a device found !
    case ESP_BT_GAP_DISC_RES_EVT: {
        update_device_info(param);
        break;
    }
	case ESP_BT_GAP_DISC_STATE_CHANGED_EVT: {
        if (param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STOPPED) {
            ESP_LOGI(GAP_TAG, "Device discovery stopped.");
        } else if (param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STARTED) {
            ESP_LOGI(GAP_TAG, "Discovery started.");
        }
        break;
    } 
	case ESP_BT_GAP_RMT_SRVC_REC_EVT:
    default: {
        ESP_LOGI(GAP_TAG, "event not 'cased': %d", event);
        break;
    }
    }
    return;
}

static void bt_app_gap_start_up(void *arg) //bluetooth TASK
{
	while (true)
	{
		const char* dev_name = "ESP_GAP_INQRUIY";
		esp_bt_dev_set_device_name(dev_name);

		/* set discoverable and connectable mode, wait to be connected */
		esp_bt_gap_set_scan_mode(ESP_BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE);

		/* register GAP callback function */
		esp_bt_gap_register_callback(bt_app_gap_cb);

		/* inititialize device information and status */
		app_gap_cb_t *p_dev = &m_dev_info;
		memset(p_dev, 0, sizeof(app_gap_cb_t));

		/* start to discover nearby Bluetooth devices */
		p_dev->state = APP_GAP_STATE_DEVICE_DISCOVERING;
		esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 10, 0);

		vTaskDelay(20000 / portTICK_PERIOD_MS);
		ESP_LOGI(GAP_TAG, "Cancel device discovery ...");
		esp_bt_gap_cancel_discovery();
		//wait 3 seconds more (handling already thrown exceptions)
		vTaskDelay(3000 / portTICK_PERIOD_MS);

		//signal main task to handle the event : bluetooth devices scanned
		xEventGroupSetBits(xEventBits, BLUETOOTH_SCAN_BIT);

		vTaskDelay(300000 / portTICK_PERIOD_MS); //wait for 5 minutes before scanning again
	}
}


//-------------------------------- UART with arduino --------------------------------//
int sendDataUART(const char* logName, const char* data)
{
    const int len = strlen(data);
    const int txBytes = uart_write_bytes(UART_NUM_1, data, len);
    ESP_LOGI(logName, "Wrote %d bytes : %s", txBytes, data);
    return txBytes;
}

static void tx_task(void *arg)
{
	printf("uart_tx_task task's priority : %d \n", (uxTaskPriorityGet(NULL)));
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);

	char msg2Arduino[QUEUE_ITEM_SIZE/100];
    while (1) //check if esp must send something
	{
		if (xQueueReceive( uart_send_queue, &msg2Arduino, portMAX_DELAY) != pdPASS)
		{
			ESP_LOGI(TX_TASK_TAG, "Nothing was received from the Queue (even after blocking)");
		}
		else
		{
			sendDataUART(TX_TASK_TAG, msg2Arduino);
		}
		memset(&msg2Arduino, 0, sizeof(msg2Arduino));
    }
}

void *rx_thread(void *args)
{
    static const char *RX_TASK_TAG = "RX_TASK";
    esp_log_level_set(RX_TASK_TAG, ESP_LOG_INFO);
    uint8_t* data = (uint8_t*) malloc(RX_BUF_SIZE+1);
    std::string send2Server;
    const char delim[2] = "\n";
    char *token, *charInfo, *red, *green, *blue;
    int lastExclamationPosition;
    Client infoClient;
    while (true) 
    {	//RX_BUF_SIZE-1 , so that I can add a \n\0 if needed
        const int rxBytes = uart_read_bytes(UART_NUM_1, data, RX_BUF_SIZE-2, 1000 / portTICK_RATE_MS);
        if (rxBytes > 0) 
    	{
          data[rxBytes] = 0;
          ESP_LOGI(RX_TASK_TAG, "Read %d bytes: \n'%s'\n end of message\n", rxBytes, data);
          //ESP_LOG_BUFFER_HEXDUMP(RX_TASK_TAG, data, rxBytes, ESP_LOG_INFO);
    	
    		//process response
    		send2Server = "<";

    		charInfo = reinterpret_cast<char *>(data);
    		
    		if (rxBytes == RX_BUF_SIZE-2) //overflow. cut the response
    		{
    			lastExclamationPosition = strrchr(charInfo, '!') - charInfo;
    			charInfo[lastExclamationPosition + 1] = '\n'; 
    			charInfo[lastExclamationPosition + 2] = '\0'; 
    		}

    		send2Server = send2Server + std::string(charInfo);
    		if (send2Server.find("-") != std::string::npos)
    		{
				printf("###|IF it is\n");
    			//send it quickly
    			try
    			{
    				servableClient.sendData(send2Server);
    			}catch (SocketException &e)
    			{
    				cout <<e.what() << e.getMsg() <<endl;
    			}

    		}else
    		{
				printf("###|ELSE it is\n");

    			//parse the string

    			token = strtok(charInfo, delim);

    			while(token != NULL)
    			{
    				switch (token[0])
    				{
    					case '0':
    					case '1':
    					case '2':
    					case '3':
    						ledsState[atoi(token)] = atoi(token + 2);
    						break;
    					case '4':
    						//look for ':' & next is red
    						red = strchr(token, ':');
    						ledsState[4] = atoi(red+1);

    						green = strchr(red, ',');
    						ledsState[5] = atoi(green+1);

    						blue = strchr(green+1, ',');
    						ledsState[6] = atoi(blue+1);

    						break;
    					case '5':
    						measurements[0] = atof(token + 2);
    						break;
    					case '6':
    						measurements[1] = atof(token + 2);
    						break;
    					case '7':
    						measurements[2] = atof(token + 2);
    						break;
    					case '8':
    						measurements[3] = atof(token + 2);
    						break;
    					case '9':
    						doorState = atoi(token+2);
    						break;
    					case '!': //end of message //MUST PUT A MUTEX HERE
    						//send initiatting data
    						pthread_mutex_lock(&lockSocket);
    						try
    						{
    							infoClient.createSocket(EZPANDA_IP, "5678");
    							vTaskDelay(1500 / portTICK_PERIOD_MS);
    							infoClient.sendData(send2Server);
    							string response = infoClient.recvData();
    							cout <<"###|" <<response <<endl;
    							infoClient.closeClientSocket();
    						}catch (SocketException &e)
    						{
    							cout <<e.what() << e.getMsg() <<endl;
    						}
    						pthread_mutex_unlock(&lockSocket);
    						break;
    				}
    				token = strtok(NULL,delim); //exclusive on delimiter
    			}
    		
    		}
    	}
    }
   	free(data);
}


//-------------------------------- SERVER THREAD --------------------------------//
void *servering(void *args)//this function is run by the server thread
{
	cout <<"###|Starting servering thread\n";
	string command, response="esp here reee !\n";

	////tdlt
	//bool APACHE_LED_STATE = 0;
	//gpio_set_direction(GPIO_APACHE_LED, GPIO_MODE_OUTPUT);
	//gpio_set_level(GPIO_APACHE_LED, APACHE_LED_STATE);
	try
	{
		servableClient.createSocket(EZPANDA_IP, "4567");

		const char *msg2Arduino;
		while(1)
		{
			command = "";
			response = "";
			command = servableClient.recvData();
			cout <<"###|apache command :" <<command <<endl;

			////proccess command
			if (command.at(0) == '<') //arduino command
			{
				command = command.substr(1); //strip off '<'
				msg2Arduino = command.c_str();
				xQueueSendToBack(uart_send_queue, msg2Arduino, portMAX_DELAY);
				// the request will be handled by tx_task & rx_thread
			}else if (command.at(0) == '&')//polling me
			{ 
				response = "yes!\n";
				servableClient.sendData(response);
				//cout <<"###|apache response :" <<response <<endl;
			}


			//command = command.substr (0,command.length()-5);
			//if (command.at(0) == '?')
			//{
			//     APACHE_LED_STATE = !APACHE_LED_STATE;
			//     gpio_set_level(GPIO_APACHE_LED, APACHE_LED_STATE);
			//}


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
	printf("                    ╲╲╲╲◢◣▁▁▁▁▁◢◣╱╱╱╱\n");
	printf("                    ╲╲╲╲◥▔▔▔▔▔▔▔◤╱╱╱╱\n");
	printf("                    ╲╲╲╲▕▏▇▏┈▕▇▕▏╱╱╱╱\n");
	printf("                    ╲╲╲╲▕▏◤┈▼┈◥▕▏╱╱╱╱\n");
	printf("                    ╲╲╲╲▕▏╲╰━╯╱▕▏╱╱╱╱\n");
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
	xEventBits = xEventGroupCreate();

	//continue to main program
	esp_err_t ret;
	ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK( ret );

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
	
	//----initialize UART-----//
	uart_config_t uart_config = {};
	uart_config.baud_rate = 115200;
	uart_config.data_bits = UART_DATA_8_BITS;
	uart_config.parity = UART_PARITY_DISABLE;
	uart_config.stop_bits = UART_STOP_BITS_1;
	uart_config.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
    uart_param_config(UART_NUM_1, &uart_config);

    uart_set_pin(UART_NUM_1, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    //@arg 3 : I am not using a buffer for sending data.
	// So, TX function will block task untill all data have been sent out.
    uart_driver_install(UART_NUM_1, RX_BUF_SIZE * 10, 0, 0, NULL, 0);

	//-----initialize freeRTOS Queue and the attending tasks-----//
	if ((uart_send_queue = xQueueCreate(QUEUE_LENGTH, QUEUE_ITEM_SIZE)) == NULL)
		ESP_LOGE(QUEUE_TAG, "freeRTOS Queue could not be created");

	//--------------------------Bluetooth configuration---------------------------//
	esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if ((ret = esp_bt_controller_init(&bt_cfg)) != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bt_controller_enable(ESP_BT_MODE_BTDM)) != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bluedroid_init()) != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s initialize bluedroid failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bluedroid_enable()) != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s enable bluedroid failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

	//wait indefinetely untill esp32 gets connected
	xEventGroupWaitBits(xEventBits, CONNECTED_BIT, false, true, portMAX_DELAY);

	printf("###|main task's priority : %d \n", (uxTaskPriorityGet(NULL)));

	//----------------------------INTERNET !---------------------------------//
	tcpip_adapter_ip_info_t ip_info;
	ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info));
	printf("###|esp32 : IP Address  : %s\n", ip4addr_ntoa(&ip_info.ip));
	printf("###|esp32 : Subnet Mask : %s\n", ip4addr_ntoa(&ip_info.netmask));
	printf("###|esp32 : Gateway     : %s\n", ip4addr_ntoa(&ip_info.gw));
	
	
	
	
	//start TX uart task
    xTaskCreate(tx_task, "uart_tx_task", 1024*2, NULL, configMAX_PRIORITIES-1, NULL);
	//start bluetooth task
	xTaskCreate(bt_app_gap_start_up, "connected_to_wifi_program", 2048, NULL, 5, NULL);

    //creating pthread for server 
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, servering, NULL))
         printf("###|COULD NOT start server thread.\n");
	//creating pthread for rx uart (not a task because socket exceptions are needed)
	//first intilialize the mutex between the thread & the main thread

	if (pthread_mutex_init(&lockSocket, NULL) != 0)
		ESP_LOGE(USER_TAG, "Could not initialize mutex");
    pthread_t rxUART_thread;
    if (pthread_create(&rxUART_thread, NULL, rx_thread, NULL))
         printf("###|COULD NOT start server thread.\n");
	

    
	//initialize data
	//ask for full report
	const char *msg2Arduino = "*!\n";
	//std::string str = "*!\n";
	//queue_msg2Arduino = str.c_str();
	xQueueSendToBack(uart_send_queue, msg2Arduino, portMAX_DELAY);

	Client client;
	while (true)
	{
		string deviceReport = "@";
		//@arg3 : clear the bits we wait for. 
		xEventGroupWaitBits(xEventBits, BLUETOOTH_SCAN_BIT, pdTRUE, true, portMAX_DELAY);
		//bluetooth scan happened. check unordered map bdaName_map
		for (auto it = bdaName_map.begin(); it != bdaName_map.end(); it++)
		{
			// it->first is the bda key
			// it->second is the bda name
			deviceReport += it->first + ':' + it->second + '\n';
		}
		if (!(deviceReport == "a"))
		{
			deviceReport += "!\n";
			pthread_mutex_lock(&lockSocket);
			try
			{
				client.createSocket(EZPANDA_IP, "5678");
				client.sendData(deviceReport);
				string response = client.recvData();
				cout <<"###|" <<response <<endl;
				client.closeClientSocket();
			}catch (SocketException &e)
			{
				cout <<e.what() << e.getMsg() <<endl;
			}
			pthread_mutex_unlock(&lockSocket);

		}
		//clear map
		bdaName_map.clear();
        vTaskDelay(10 / portTICK_PERIOD_MS);
	}
	////server-side code
    //
    //try
    //{
    //     Server server("9865");
    //     server.createSocket();
    //     while (true)
    //     {
    //          string request = server.wait4ClientRequest();
    //          string response = "You said :" + request;
    //          server.sendData(response);
    //          server.closeClientSocket();
    //     }
    //}catch (SocketException &e)
    //{
    //     cout <<e.what() << e.getMsg();
    //}
    //
    ////client-side code
    //while(1)
    //{
    //     try
    //     {
    //          Client client;
    //          client.createSocket(EZPANDA_IP, "5678");
    //          vTaskDelay(1500 / portTICK_PERIOD_MS);
    //          client.sendData("Light1:1\nLight2:0\nServo:1\nEnergyTransmitter:0!\n");
    //          string response = client.recvData();
    //          cout <<"###|" <<response <<endl;
    //          client.closeClientSocket();
    //     }catch (SocketException &e)
    //     {
    //          cout <<e.what() << e.getMsg() <<endl;
    //     }

    //     vTaskDelay(25000 / portTICK_PERIOD_MS);
    //}

    /* wait for the server thread to finish */
    if(pthread_join(server_thread, NULL)) {
         printf("###|COULD NOT join server thread.\n");
         esp_restart();
    }
    if(pthread_join(rxUART_thread, NULL)) {
         printf("###|COULD NOT join rxUART thread.\n");
         esp_restart();
    }
	pthread_mutex_destroy(&lockSocket);
}
