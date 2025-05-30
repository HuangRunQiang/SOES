/*
 * 根据GNU通用公共许可证第2版及其例外条款授权。有关完整的许可证信息，请参见项目根目录中的LICENSE文件
 */

/** \file
 * \brief
 * esc_eoe.c的头文件
 */

#ifndef __esc_eoe__
#define __esc_eoe__

#include <cc.h>

typedef struct eoe_pbuf
{
   /** 指向用于TCP/IP栈的lwip buffer类型的指针（非必需） */
   void * pbuf;
   /** 指向要发送或读取的lwip buffer的指针 */
   uint8_t * payload;
   /** lwip buffer中数据的长度 */
   size_t len;
} eoe_pbuf_t;

typedef struct eoe_cfg
{
   /** 获取用于存储接收帧的lwipbuffer */
   void (*get_buffer) (eoe_pbuf_t * ebuf);
   /** 释放lwip buffer */
   void (*free_buffer) (eoe_pbuf_t * ebuf);
   /** 读取本地设置并更新要传递给EtherCAT主站的EtherCAT变量 */
   int  (*load_eth_settings) (void);
   /** 读取EtherCAT主站提供的设置并存储到本地设置 */
   int  (*store_ethernet_settings) (void);
   /** TCP/IP栈中帧接收函数，
    * 调用者应释放lwip buffer
    */
   void (*handle_recv_buffer) (uint8_t port, eoe_pbuf_t * ebuf);
   /** 获取要发送的lwip buffer */
   int (*fetch_send_buffer) (uint8_t port, eoe_pbuf_t * ebuf);
   /** 通知应用程序片段已发送 */
   void (*fragment_sent_event) (void);
} eoe_cfg_t;

int EOE_ecat_get_mac (uint8_t port, uint8_t mac[]);
int EOE_ecat_get_ip (uint8_t port, uint32_t * ip);
int EOE_ecat_get_subnet (uint8_t port, uint32_t * subnet);
int EOE_ecat_get_gateway (uint8_t port, uint32_t * default_gateway);
int EOE_ecat_get_dns_ip (uint8_t port, uint32_t * dns_ip);
int EOE_ecat_get_dns_name (uint8_t port, char * dns_name);
int EOE_ecat_set_mac (uint8_t port, uint8_t mac[]);
int EOE_ecat_set_ip (uint8_t port, uint32_t ip);
int EOE_ecat_set_subnet (uint8_t port, uint32_t subnet);
int EOE_ecat_set_gateway (uint8_t port, uint32_t default_gateway);
int EOE_ecat_set_dns_ip (uint8_t port, uint32_t dns_ip);
int EOE_ecat_set_dns_name (uint8_t port, char * dns_name);

void EOE_config (eoe_cfg_t * cfg);
void EOE_init (void);
void ESC_eoeprocess (void);
void ESC_eoeprocess_tx (void);

#endif
