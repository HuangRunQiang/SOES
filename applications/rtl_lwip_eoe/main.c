#include <kern.h>
#include <xmc4.h>
#include <bsp.h>
#include "esc.h"
#include "esc_eoe.h"
#include "esc_hw.h"
#include "ecat_slv.h"
#include "options.h"
#include "utypes.h"
#include <lwip/sys.h>
#include <lwip/netifapi.h>
#include <netif/etharp.h>
#include <string.h>

#define CFG_HOSTNAME "xmc48relax" // 主机名配置

static struct netif * found_if; // 找到的网络接口
static mbox_t * pbuf_mbox; // 缓冲区邮箱
static uint8_t mac_address[6] = {0x1E, 0x30, 0x6C, 0xA2, 0x45, 0x5E}; // MAC地址

static void appl_get_buffer (eoe_pbuf_t * ebuf); // 获取缓冲区
static void appl_free_buffer (eoe_pbuf_t * ebuf); // 释放缓冲区
static int appl_load_eth_settings (void); // 加载以太网设置
static int appl_store_ethernet_settings (void); // 存储以太网设置
static void appl_handle_recv_buffer (uint8_t port, eoe_pbuf_t * ebuf); // 处理接收缓冲区
static int appl_fetch_send_buffer (uint8_t port, eoe_pbuf_t * ebuf); // 获取发送缓冲区

/* 应用程序变量 */
_Objects Obj;

extern sem_t * ecat_isr_sem; // EtherCAT中断信号量

struct netif * net_add_interface (err_t (*netif_fn) (struct netif * netif))
{
   struct netif * netif;
   ip_addr_t ipaddr;
   ip_addr_t netmask;
   ip_addr_t gateway;
   err_enum_t error;

   netif = malloc (sizeof(struct netif)); // 为网络接口分配内存
   UASSERT (netif != NULL, EMEM); // 确保分配成功

   /* 设置默认（零）值 */
   ip_addr_set_zero (&ipaddr);
   ip_addr_set_zero (&netmask);
   ip_addr_set_zero (&gateway);

   /* 让lwIP TCP/IP线程初始化并添加接口。该接口将在调用net_configure()之前处于关闭状态。 */
   error = netifapi_netif_add (
         netif, &ipaddr, &netmask, &gateway, NULL, netif_fn, tcpip_input);
   UASSERT (error == ERR_OK, EARG); // 确保添加成功

   return netif;
}

void cb_get_inputs (void) // 获取输入回调
{
   static int count;
   Obj.Buttons.Button1 = gpio_get(GPIO_BUTTON1); // 获取按钮状态
   if(Obj.Buttons.Button1 == 0) // 按钮按下
   {
      count++;
      if(count > 1000) // 超过阈值
      {
         ESC_ALstatusgotoerror((ESCsafeop | ESCerror), ALERR_WATCHDOG); // 进入错误状态
      }
   }
   else
   {
      count = 0; // 重置计数
   }
}

void cb_set_outputs (void) // 设置输出回调
{
   gpio_set(GPIO_LED1, Obj.LEDgroup0.LED0); // 设置LED1状态
   gpio_set(GPIO_LED2, Obj.LEDgroup1.LED1); // 设置LED2状态
}

void cb_state_change (uint8_t * as, uint8_t * an) // 状态变化回调
{
   if (*as == SAFEOP_TO_OP) // 从安全操作到操作
   {
      /* 启用看门狗中断 */
      ESC_ALeventmaskwrite(ESC_ALeventmaskread() | ESCREG_ALEVENT_WD);
   }

   /* 如果我们处于INIT状态，清理数据 */
   if ((*as == INIT_TO_PREOP) && (*an == ESCinit))
   {
      struct pbuf *p;
      int i = 0;
      while(mbox_fetch_tmo(pbuf_mbox, (void **)&p, 0) == 0) // 从邮箱中获取pbuf
      {
         pbuf_free(p); // 释放pbuf
         i++;
      }
      if(i)
      {
         rprintf("清理的eoe pbuf: %d\n",i); // 输出清理的pbuf数量
      }
      EOE_init(); // 初始化EOE
   }
}

/* 获取缓冲区 */
static void appl_get_buffer (eoe_pbuf_t * ebuf)
{
   struct pbuf * p = pbuf_alloc(PBUF_RAW, PBUF_POOL_BUFSIZE, PBUF_POOL); // 分配pbuf

   if(p != NULL)
   {
      ebuf->payload = p->payload; // 设置负载
      ebuf->pbuf = p; // 设置pbuf
      ebuf->len = p->len; // 设置长度
   }
   else
   {
      ebuf->payload = NULL; // 设置负载为NULL
      ebuf->pbuf = NULL; // 设置pbuf为NULL
      ebuf->len = p->len; // 设置长度
   }
}

/* 释放缓冲区 */
static void appl_free_buffer (eoe_pbuf_t * ebuf)
{
   if(ebuf->pbuf != NULL)
   {
      pbuf_free(ebuf->pbuf); // 释放pbuf
   }
}

/* 从站处理接收到的 获取IP请求 */
static int appl_load_eth_settings (void)
{
   /*
    * ip_addr_t ip;
    * IP4_ADDR (&ip, 192, 168, 9, 200) // 设置IP地址
    * ip.addr = ntohl(ip.addr);
    * EOE_ecat_set_ip(); // 设置IP
    */
   return 0; // 返回0表示成功
}

/* 从站处理接收到的设置IP请求帧 */
static int appl_store_ethernet_settings (void)
{
   int ret = 0; // 返回值初始化
   ip_addr_t ip;
   ip_addr_t netmask;
   ip_addr_t gateway;

   /* 获取接收到的IP信息，IP以主机uint32_t格式返回 */
   if(EOE_ecat_get_ip(0, &ip.addr) == -1) // 获取IP
   {
      ret = -1; // 错误处理
   }
   else if(EOE_ecat_get_subnet(0, &netmask.addr) == -1) // 获取子网掩码
   {
      ret = -1; // 错误处理
   }
   else if(EOE_ecat_get_gateway(0, &gateway.addr) == -1) // 获取网关
   {
      ret = -1; // 错误处理
   }
   else
   {
      ip.addr = htonl(ip.addr); // 转换为网络字节序
      netmask.addr = htonl(netmask.addr);
      gateway.addr = htonl(gateway.addr);
      /* 配置TCP/IP网络栈。DNS服务器和主机名未设置。 */
      net_configure(found_if, &ip, &netmask, &gateway, NULL, CFG_HOSTNAME);
      net_link_up(found_if); // 网络连接
      if (netif_is_up(found_if)) // 检查网络接口是否已启动
      {
         rprintf("网络接口已启动 (%d.%d.%d.%d)\n",
                  ip4_addr1(&found_if->ip_addr),
                  ip4_addr2(&found_if->ip_addr),
                  ip4_addr3(&found_if->ip_addr),
                  ip4_addr4(&found_if->ip_addr));
      }
      else
      {
         rprintf("网络接口未启动\n");
      }
   }
   return ret; // 返回结果
}

/* 从站把接收的EOE帧数据给到lwip。 */
static void appl_handle_recv_buffer (uint8_t port, eoe_pbuf_t * ebuf)
{
   struct pbuf * p = ebuf->pbuf;
   p->len = p->tot_len = ebuf->len; // 设置长度
   if(ebuf->pbuf != NULL)
   {
      /* 虚拟代码，将类型为0x88A4U的L2帧回传给EtherCAT主站。 */
      struct eth_hdr *ethhdr;
      uint16_t type;
      ethhdr = p->payload;
      type = htons(ethhdr->type); // 转换类型
      if (type == 0x88A4U) // 检查类型
      {
         if(mbox_post_tmo(pbuf_mbox, p, 0)) // 尝试将pbuf发送到邮箱
         {
            pbuf_free(p); // 释放pbuf
            rprintf("传输帧超时，邮箱满？\n");
         }
         else
         {
            sem_signal(ecat_isr_sem); // 发送信号
         }
      }
      /* 将以太网帧正常传递给lwIP处理 */
      else if (found_if->input(p, found_if) != 0)
      {
         pbuf_free(p); // 释放pbuf
      }
   }
}

/* 获取邮箱中经过lwip响应后的数据，发送出去给主站 */
static int appl_fetch_send_buffer (uint8_t port, eoe_pbuf_t * ebuf)
{
   int ret;
   struct pbuf *p;

   if(mbox_fetch_tmo(pbuf_mbox, (void **)&p, 0)) // ---------从邮箱获取eoe响应数据----------
   {
      ebuf->pbuf = NULL; // 设置pbuf为NULL
      ebuf->payload = NULL; // 设置负载为NULL
      ret = -1; // 错误处理
   }
   else
   {
      ebuf->pbuf = p; // 设置pbuf
      ebuf->payload = p->payload; // 设置负载
      ebuf->len = p->tot_len; // 设置长度
      ret = ebuf->len; // 返回长度
   }
   return ret; // 返回结果
}

/* lwIP的linkout发送函数，获取经过lwip响应的数据帧，将以太网帧发送到lwip网口。 */
static err_t transmit_frame (struct netif *netif, struct pbuf *p)
{
 
   if(mbox_post_tmo(pbuf_mbox, p, 0))  /* --------将lwip响应后的数据发送给从站邮箱 ----------*/
   {
      rprintf("传输帧超时，邮箱满？\n");
   }
   else
   {
      /* 创建pbuf引用以保持缓冲区在发送过程中存活 */
      pbuf_ref(p);
      sem_signal(ecat_isr_sem); // 发送信号
   }
   return ERR_OK; // 返回成功
}

/* 创建一个虚拟ethercat网口（即lwip网络接口） */
err_t eoe_netif_init (struct netif * netif)
{
   rprintf("EOE eoe_netif_init 被调用\n");

   /* 初始化netif */
   netif->name[0] = 'e'; // 设置接口名称
   netif->name[1] = 'c';
   netif->output = etharp_output; // 设置输出函数
   netif->linkoutput = transmit_frame; // 设置链接输出
   netif->mtu = 1500; // 最大传输单元
   netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP; // 设置标志
   netif->hwaddr_len = ETHARP_HWADDR_LEN; // 硬件地址长度
   memcpy(netif->hwaddr, mac_address, sizeof(netif->hwaddr)); // 复制MAC地址

   return ERR_OK; // 返回成功
}

/* 发送事件的回调，我们触发堆栈周期以处理邮箱流量 */
void eoe_frame_sent (void)
{
   sem_signal(ecat_isr_sem); // 发送信号
}

int main (void)
{
   static esc_cfg_t config = // ESC配置
   {
      .user_arg = NULL,
      .use_interrupt = 1,
      .watchdog_cnt = INT32_MAX, // 使用硬件SM看门狗
      .set_defaults_hook = NULL,
      .pre_state_change_hook = NULL,
      .post_state_change_hook = cb_state_change, // 状态变化后回调
      .application_hook = NULL,
      .safeoutput_override = NULL,
      .pre_object_download_hook = NULL,
      .post_object_download_hook = NULL,
      .rxpdo_override = NULL,
      .txpdo_override = NULL,
      .esc_hw_interrupt_enable = ESC_interrupt_enable,
      .esc_hw_interrupt_disable = ESC_interrupt_disable,
      .esc_hw_eep_handler = ESC_eep_handler,
      .esc_check_dc_handler = NULL
   };

   /* EoE的配置参数
    * 与TCP/IP堆栈交互的函数回调
    */
   static eoe_cfg_t eoe_config =
   {
      .get_buffer = appl_get_buffer,
      .free_buffer = appl_free_buffer,
      .load_eth_settings = appl_load_eth_settings,
      .store_ethernet_settings = appl_store_ethernet_settings,
      .handle_recv_buffer = appl_handle_recv_buffer,
      .fetch_send_buffer = appl_fetch_send_buffer,
      .fragment_sent_event = eoe_frame_sent,
   };

   /* 创建一个邮箱用于TCP/IP堆栈与EtherCAT堆栈之间的进程间通信 */
   pbuf_mbox = mbox_create(10);
   /* 设置虚拟接口 */
   found_if = net_add_interface(eoe_netif_init);
   if(found_if == NULL)
   {
      rprintf("警告！创建EtherCAT网络接口失败\n");
   }
   /* 初始化EoE */
   EOE_config(&eoe_config);

   rprintf("你好，世界\n");
   ecat_slv_init(&config); // 初始化EtherCAT从站

   /* 堆栈从中断和esc_hw.c中的工作线程运行 */

   return 0; // 返回0表示成功
}
