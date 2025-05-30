/*
 * 根据GNU通用公共许可证第2版及其例外条款授权。有关完整的许可证信息，请参见项目根目录中的LICENSE文件
 */

/** \file
 * \brief
 * 以太网在EtherCAT上的模块（EoE）。
 */

#include <cc.h>
#include <string.h>
#include "esc.h"
#include "esc_eoe.h"


#if defined(EC_BIG_ENDIAN)
#define EOE_HTONS(x) (x)
#define EOE_NTOHS(x) (x)
#define EOE_HTONL(x) (x)
#define EOE_NTOHL(x) (x)
#else
#define EOE_HTONS(x) ((((x) & 0x00ffU) << 8) | (((x) & 0xff00U) >> 8))
#define EOE_NTOHS(x) EOE_HTONS(x)
#define EOE_HTONL(x) ((((x) & 0x000000ffU) << 24) | \
                     (((x) & 0x0000ff00U) <<  8) | \
                     (((x) & 0x00ff0000U) >>  8) | \
                     (((x) & 0xff000000U) >> 24))
#define EOE_NTOHL(x) EOE_HTONL(x)
#endif /* #if defined(EC_BIG_ENDIAN) */

#define EOE_MAKEU32(a,b,c,d) (((uint32_t)((a) & 0xff) << 24) | \
                            ((uint32_t)((b) & 0xff) << 16) | \
                            ((uint32_t)((c) & 0xff) << 8)  | \
                            (uint32_t)((d) & 0xff))

/** 从4字节地址获取一个字节 */
#define eoe_ip4_addr1(ipaddr) (((const uint8_t*)(&(ipaddr)->addr))[0])
#define eoe_ip4_addr2(ipaddr) (((const uint8_t*)(&(ipaddr)->addr))[1])
#define eoe_ip4_addr3(ipaddr) (((const uint8_t*)(&(ipaddr)->addr))[2])
#define eoe_ip4_addr4(ipaddr) (((const uint8_t*)(&(ipaddr)->addr))[3])

/** 根据四个字节部分设置IP地址 */
#define EOE_IP4_ADDR_TO_U32(ipaddr,a,b,c,d)  \
   (ipaddr)->addr = EOE_HTONL(EOE_MAKEU32(a,b,c,d))

/** 头帧信息 1 */
#define EOE_HDR_FRAME_TYPE_OFFSET      0
#define EOE_HDR_FRAME_TYPE             (0xF << 0)
#define EOE_HDR_FRAME_TYPE_SET(x)      ((uint16_t)(((x) & 0xF) << 0))
#define EOE_HDR_FRAME_TYPE_GET(x)      (((x) >> 0) & 0xF)
#define EOE_HDR_FRAME_PORT_OFFSET      4
#define EOE_HDR_FRAME_PORT             (0xF << 4)
#define EOE_HDR_FRAME_PORT_SET(x)      ((uint16_t)(((x) & 0xF) << 4))
#define EOE_HDR_FRAME_PORT_GET(x)      (((x) >> 4) & 0xF)
#define EOE_HDR_LAST_FRAGMENT_OFFSET   8
#define EOE_HDR_LAST_FRAGMENT          (0x1 << 8)
#define EOE_HDR_LAST_FRAGMENT_SET(x)   ((uint16_t)(((x) & 0x1) << 8))
#define EOE_HDR_LAST_FRAGMENT_GET(x)   (((x) >> 8) & 0x1)
#define EOE_HDR_TIME_APPEND_OFFSET     9
#define EOE_HDR_TIME_APPEND            (0x1 << 9)
#define EOE_HDR_TIME_APPEND_SET(x)     ((uint16_t)(((x) & 0x1) << 9))
#define EOE_HDR_TIME_APPEND_GET(x)     (((x) >> 9) & 0x1)
#define EOE_HDR_TIME_REQUEST_OFFSET    10
#define EOE_HDR_TIME_REQUEST           (0x1 << 10)
#define EOE_HDR_TIME_REQUEST_SET(x)    ((uint16_t)(((x) & 0x1) << 10))
#define EOE_HDR_TIME_REQUEST_GET(x)    (((x) >> 10) & 0x1)

/** 头帧信息 2 */
#define EOE_HDR_FRAG_NO_OFFSET         0
#define EOE_HDR_FRAG_NO                (0x3F << 0)
#define EOE_HDR_FRAG_NO_SET(x)         ((uint16_t)(((x) & 0x3F) << 0))
#define EOE_HDR_FRAG_NO_GET(x)         (((x) >> 0) & 0x3F)
#define EOE_HDR_FRAME_OFFSET_OFFSET    6
#define EOE_HDR_FRAME_OFFSET           (0x3F << 6)
#define EOE_HDR_FRAME_OFFSET_SET(x)    ((uint16_t)(((x) & 0x3F) << 6))
#define EOE_HDR_FRAME_OFFSET_GET(x)    (((x) >> 6) & 0x3F)
#define EOE_HDR_FRAME_NO_OFFSET        12
#define EOE_HDR_FRAME_NO               (0xF << 12)
#define EOE_HDR_FRAME_NO_SET(x)        ((uint16_t)(((x) & 0xF) << 12))
#define EOE_HDR_FRAME_NO_GET(x)        (((x) >> 12) & 0xF)

/** EOE 参数 */
#define EOE_PARAM_OFFSET                  4
#define EOE_PARAM_MAC_INCLUDE             (0x1 << 0)
#define EOE_PARAM_IP_INCLUDE              (0x1 << 1)
#define EOE_PARAM_SUBNET_IP_INCLUDE       (0x1 << 2)
#define EOE_PARAM_DEFAULT_GATEWAY_INCLUDE (0x1 << 3)
#define EOE_PARAM_DNS_IP_INCLUDE          (0x1 << 4)
#define EOE_PARAM_DNS_NAME_INCLUDE        (0x1 << 5)

/** EoE 帧类型 */
#define EOE_FRAG_DATA                  0
#define EOE_INIT_RESP_TIMESTAMP        1
#define EOE_INIT_REQ                   2 /* 规范设置IP请求 */
#define EOE_INIT_RESP                  3 /* 规范设置IP响应 */
#define EOE_SET_ADDR_FILTER_REQ        4
#define EOE_SET_ADDR_FILTER_RESP       5
#define EOE_GET_IP_PARAM_REQ           6
#define EOE_GET_IP_PARAM_RESP          7
#define EOE_GET_ADDR_FILTER_REQ        8
#define EOE_GET_ADDR_FILTER_RESP       9

/** 定义可用端口数量（目前仅支持一个） */
#define EOE_NUMBER_OF_PORTS   1
#define EOE_PORT_INDEX(x)     ((x > 0) ? (x - 1) : 0)
/** DNS长度根据ETG 1000.6 */
#define EOE_DNS_NAME_LENGTH  32
/** 不包括VLAN的以太网地址长度 */
#define EOE_ETHADDR_LENGTH    6
/** IPv4地址长度 */
#define EOE_IP4_LENGTH        4U /* sizeof(uint32_t) */

/** EOE IPv4地址（网络字节序） */
struct eoe_ip4_addr {
  uint32_t addr;
};
typedef struct eoe_ip4_addr eoe_ip4_addr_t;

/** EOE以太网地址 */
CC_PACKED_BEGIN
typedef struct CC_PACKED eoe_ethaddr
{
  uint8_t addr[EOE_ETHADDR_LENGTH];
} eoe_ethaddr_t;
CC_PACKED_END

typedef struct
{
   /** 指向当前RX lwip buffer的指针 */
   eoe_pbuf_t rxebuf;
   /** 指向当前TX lwip buffer的指针 */
   eoe_pbuf_t txebuf;

   /** 当前RX片段编号 */
   uint8_t rxfragmentno;
   /** 当前帧的完整RX帧大小 */
   uint32_t rxframesize;
   /** 当前帧中的RX数据偏移量 */
   uint32_t rxframeoffset;
   /** 当前RX帧编号 */
   uint16_t rxframeno;

   /** 当前TX片段编号 */
   uint8_t txfragmentno;
   /** 当前帧的完整TX帧大小 */
   uint32_t txframesize;
   /** 当前帧中的TX数据偏移量 */
   uint32_t txframeoffset;
} _EOEvar;

/** EoE IP请求结构 */
typedef struct eoe_param
{
   uint8_t mac_set:1;
   uint8_t ip_set:1;
   uint8_t subnet_set:1;
   uint8_t default_gateway_set:1;
   uint8_t dns_ip_set:1;
   uint8_t dns_name_set:1;
   eoe_ethaddr_t mac;
   eoe_ip4_addr_t ip;
   eoe_ip4_addr_t subnet;
   eoe_ip4_addr_t default_gateway;
   eoe_ip4_addr_t dns_ip;
   char dns_name[EOE_DNS_NAME_LENGTH];
} eoe_param_t;

/** 主EoE状态数据数组。结构在EoE接收和发送操作期间填充当前信息变量。 */
static _EOEvar EOEvar;

/** 主FoE配置指针数据数组。结构由应用程序分配并填充，定义所需的偏好。 */
static eoe_cfg_t * eoe_cfg;

/** 本地EoE变量，保存缓存的IP信息值。
 * 由用户应用程序设置或读取，例如TCP/IP栈。
 */
static eoe_param_t nic_ports[EOE_NUMBER_OF_PORTS];

/** 本地初始化/重置函数，在帧接收初始化时调用 */
static void EOE_init_rx ();
/** 本地初始化/重置函数，在帧发送完成时调用 */
static void EOE_init_tx ();

/** EoE工具函数，将uint32转换为EoE IP字节。
 * @param[in] ip       = uint32格式的IP
 * @param[out] byte_ip = EoE IP的第4个八位字节、第3个八位字节、第2个八位字节、第1个八位字节
 */
static void EOE_ip_uint32_to_byte (eoe_ip4_addr_t * ip, uint8_t * byte_ip)
{
   byte_ip[3] = eoe_ip4_addr1(ip); /* 第1个八位字节 */
   byte_ip[2] = eoe_ip4_addr2(ip); /* 第2个八位字节 */
   byte_ip[1] = eoe_ip4_addr3(ip); /* 第3个八位字节 */
   byte_ip[0] = eoe_ip4_addr4(ip); /* 第4个八位字节 */
}

/** EoE工具函数，将EoE IP字节转换为uint32。
 * @param[in] byte_ip = EoE IP的第4个八位字节、第3个八位字节、第2个八位字节、第1个八位字节
 * @param[out] ip     = uint32格式的IP
 */
static void EOE_ip_byte_to_uint32 (uint8_t * byte_ip, eoe_ip4_addr_t * ip)
{
   EOE_IP4_ADDR_TO_U32(ip,
         byte_ip[3],  /* 第1个八位字节 */
         byte_ip[2],  /* 第2个八位字节 */
         byte_ip[1],  /* 第3个八位字节 */
         byte_ip[0]) ;/* 第4个八位字节 */
}

/** 获取EoE缓存的MAC地址
 *
 * @param[in] port   = 获取指定端口的MAC地址
 * @param[out] mac   = 存储MAC地址的变量，应该适合EOE_ETHADDR_LENGTH
 * @return 0=成功，-1=未设置
 */
int EOE_ecat_get_mac(uint8_t port, uint8_t mac[])
{
   int ret = -1;
   int port_ix;

   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].mac_set)
      {
         memcpy(mac, nic_ports[port_ix].mac.addr,
               sizeof(nic_ports[port_ix].mac));
         nic_ports[port_ix].mac_set = 1;
         ret = 0;
      }
   }
   return ret;
}

/** 设置EoE缓存的MAC地址
 *
 * @param[in] port   = 获取指定端口的MAC地址
 * @param[in] mac    = 要存储的MAC地址
 * @return 0=成功，其他=-1。
 */
int EOE_ecat_set_mac(uint8_t port, uint8_t mac[])
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      memcpy(nic_ports[port_ix].mac.addr, mac,
            sizeof(nic_ports[port_ix].mac));
      ret = 0;
   }
   return ret;
}

/** 获取EoE缓存的IP地址
 *
 * @param[in] port  = 获取指定端口的IP地址
 * @param[out] ip   = 存储IP地址的变量
 * @return 0=成功，-1=未设置
 */
int EOE_ecat_get_ip(uint8_t port, uint32_t * ip)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].ip_set)
      {
         *ip = EOE_NTOHL(nic_ports[port_ix].ip.addr);
         ret = 0;
      }
   }
   return ret;
}

/** 设置EoE缓存的IP地址
 *
 * @param[in] port   = 获取指定端口的IP
 * @param[in] ip     = 要存储的IP地址
 * @return 0=成功，其他=-1。
 */
int EOE_ecat_set_ip(uint8_t port, uint32_t  ip)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      nic_ports[port_ix].ip.addr = EOE_HTONL(ip);
      nic_ports[port_ix].ip_set = 1;
      ret = 0;
   }
   return ret;
}

/** 获取EoE缓存的子网IP地址
 *
 * @param[in] port    = 获取指定端口的IP地址
 * @param[out] subnet = 存储IP地址的变量
 * @return 0=成功，-1=未设置
 */
int EOE_ecat_get_subnet(uint8_t port, uint32_t * subnet)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].subnet_set)
      {
         *subnet = EOE_NTOHL(nic_ports[port_ix].subnet.addr);
         ret = 0;
      }
   }
   return ret;
}

/** 设置EoE缓存的子网IP地址
 *
 * @param[in] port   = 获取指定端口的IP
 * @param[in] subnet = 要存储的IP地址
 * @return 0=成功，其他=-1。
 */
int EOE_ecat_set_subnet(uint8_t port, uint32_t subnet)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      nic_ports[port_ix].subnet.addr = EOE_HTONL(subnet);
      nic_ports[port_ix].subnet_set = 1;
      ret = 0;
   }
   return ret;
}

/** 获取EoE缓存的默认网关IP地址
 *
 * @param[in] port             = 获取指定端口的IP地址
 * @param[out] default_gateway = 存储IP地址的变量
 * @return 0=成功，-1=未设置
 */
int EOE_ecat_get_gateway(uint8_t port, uint32_t * default_gateway)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].default_gateway_set)
      {
         *default_gateway =
               EOE_NTOHL(nic_ports[port_ix].default_gateway.addr);
         ret = 0;
      }
   }
   return ret;
}

/** 设置EoE缓存的默认网关IP地址
 *
 * @param[in] port            = 获取指定端口的IP
 * @param[in] default_gateway = 要存储的IP地址
 * @return 0=成功，其他=-1。
 */
int EOE_ecat_set_gateway(uint8_t port, uint32_t default_gateway)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      nic_ports[port_ix].default_gateway.addr =
            EOE_HTONL(default_gateway);
      nic_ports[port_ix].default_gateway_set = 1;
      ret = 0;
   }
   return ret;
}

/** 获取EoE缓存的DNS IP地址
 *
 * @param[in] port    = 获取指定端口的IP地址
 * @param[out] dns_ip = 存储IP地址的变量
 * @return 0=成功，-1=未设置
 */
int EOE_ecat_get_dns_ip(uint8_t port, uint32_t * dns_ip)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].dns_ip_set)
      {
         *dns_ip = EOE_NTOHL(nic_ports[port_ix].dns_ip.addr);
         ret = 0;
      }
   }
   return ret;
}

/** 设置EoE缓存的DNS IP地址
 *
 * @param[in] port   = 获取指定端口的IP
 * @param[in] dns_ip = 要存储的IP地址
 * @return 0=成功，其他=-1。
 */
int EOE_ecat_set_dns_ip(uint8_t port, uint32_t dns_ip)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      nic_ports[port_ix].dns_ip.addr = EOE_HTONL(dns_ip);
      nic_ports[port_ix].dns_ip_set = 1;
      ret = 0;
   }
   return ret;
}

/** 获取EoE缓存的DNS名称
 *
 * @param[in] port      = 获取指定端口的DNS名称
 * @param[out] dns_name = 存储DNS名称的变量
 * @return 0=成功，-1=未设置
 */
int EOE_ecat_get_dns_name(uint8_t port, char * dns_name)
{
   int ret = -1;
   int port_ix;
   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].dns_name_set)
      {
         memcpy(dns_name,
               nic_ports[port_ix].dns_name,
               sizeof(nic_ports[port_ix].dns_name));
         ret = 0;
      }
   }
   return ret;
}

/** 设置EoE缓存的DNS名称
 *
 * @param[in] port     = 获取指定端口的DNS名称
 * @param[in] dns_name = 要存储的DNS名称
 * @return 0=成功，其他=-1。
 */
int EOE_ecat_set_dns_name(uint8_t port, char * dns_name)
{
   int ret = -1;
   int port_ix;

   if(port < EOE_NUMBER_OF_PORTS)
   {
      port_ix = EOE_PORT_INDEX(port);
      memcpy(nic_ports[port_ix].dns_name,
            dns_name,
            sizeof(nic_ports[port_ix].dns_name));
      nic_ports[port_ix].dns_name_set = 1;
      ret = 0;
   }
   return ret;
}

/** 发送简单的EoE响应帧的函数。
 *
 * @param[in] frametype1 = 响应的帧类型
 * @param[in] result     = 结果代码
 */
static void EOE_no_data_response (uint16_t frameinfo1, uint16_t result)
{
   _EOE *eoembx;
   uint8_t mbxhandle;

   /* 发送响应数据包。 */
   mbxhandle = ESC_claimbuffer ();
   if (mbxhandle)
   {
      eoembx = (_EOE *) &MBX[mbxhandle * ESC_MBXSIZE];
      eoembx->mbxheader.length = htoes (ESC_EOEHSIZE);
      eoembx->mbxheader.mbxtype = MBXEOE;
      eoembx->eoeheader.frameinfo1 = htoes(frameinfo1);
      eoembx->eoeheader.result = htoes(result);
      MBXcontrol[mbxhandle].state = MBXstate_outreq;
   }
}

/** EoE获取IP参数请求处理器。将发送获取IP参数响应。
 */
static void EOE_get_ip (void)
{
   _EOE *req_eoembx;
   _EOE *eoembx;
   uint8_t mbxhandle;
   uint16_t frameinfo1;
   uint8_t port;
   uint8_t  flags;
   uint32_t  data_offset;
   int port_ix;

   req_eoembx = (_EOE *) &MBX[0];
   frameinfo1 = etohs(req_eoembx->eoeheader.frameinfo1);
   port = EOE_HDR_FRAME_PORT_GET(frameinfo1);
   data_offset = EOE_PARAM_OFFSET;
   flags = 0;

   if(port  > EOE_NUMBER_OF_PORTS)
   {
      DPRINT("无效的端口\n");
      frameinfo1 = EOE_HDR_FRAME_PORT_SET(port);
      frameinfo1 |= EOE_INIT_RESP;
      frameinfo1 |= EOE_HDR_LAST_FRAGMENT;
      /* 返回给定端口的错误响应 */
      EOE_no_data_response(frameinfo1,
            EOE_RESULT_UNSPECIFIED_ERROR);
      return;
   }

   /* 如果需要，刷新设置 */
   if(eoe_cfg->load_eth_settings != NULL)
   {
      (void)eoe_cfg->load_eth_settings();
   }

   /* 发送响应数据包。 */
   mbxhandle = ESC_claimbuffer ();
   if (mbxhandle)
   {
      eoembx = (_EOE *) &MBX[mbxhandle * ESC_MBXSIZE];
      eoembx->mbxheader.mbxtype = MBXEOE;
      MBXcontrol[mbxhandle].state = MBXstate_outreq;
      frameinfo1 = EOE_HDR_FRAME_PORT_SET(port);
      frameinfo1 |= EOE_HDR_FRAME_TYPE_SET(EOE_GET_IP_PARAM_RESP);
      frameinfo1 |= EOE_HDR_LAST_FRAGMENT;
      eoembx->eoeheader.frameinfo1 = htoes(frameinfo1);
      eoembx->eoeheader.frameinfo2 = 0;

      /* 在获取IP请求中包含MAC */
      port_ix = EOE_PORT_INDEX(port);
      if(nic_ports[port_ix].mac_set)
      {
         flags |= EOE_PARAM_MAC_INCLUDE;
         memcpy(&eoembx->data[data_offset],
               nic_ports[port_ix].mac.addr,
               EOE_ETHADDR_LENGTH);
         /* 增加MAC地址的大小 */
         data_offset += EOE_ETHADDR_LENGTH;
      }
      /* 在获取IP请求中包含IP */
      if(nic_ports[port_ix].ip_set)
      {
         flags |= EOE_PARAM_IP_INCLUDE;
         EOE_ip_uint32_to_byte(&nic_ports[port_ix].ip,
               &eoembx->data[data_offset]);
         /* 增加uint32 IP地址的大小 */
         data_offset += EOE_IP4_LENGTH;
      }

      /* 在获取IP请求中包含子网 */
      if(nic_ports[port_ix].subnet_set)
      {
         flags |= EOE_PARAM_SUBNET_IP_INCLUDE;
         EOE_ip_uint32_to_byte(&nic_ports[port_ix].subnet,
               &eoembx->data[data_offset]);
         /* 增加uint32 IP地址的大小 */
         data_offset += EOE_IP4_LENGTH;
      }

      /* 在获取IP请求中包含默认网关 */
      if(nic_ports[port_ix].default_gateway_set)
      {
         flags |= EOE_PARAM_DEFAULT_GATEWAY_INCLUDE;
         EOE_ip_uint32_to_byte(&nic_ports[port_ix].default_gateway,
               &eoembx->data[data_offset]);
         /* 增加uint32 IP地址的大小 */
         data_offset += EOE_IP4_LENGTH;
      }
      /* 在获取IP请求中包含DNS IP */
      if(nic_ports[port_ix].dns_ip_set)
      {
         flags |= EOE_PARAM_DNS_IP_INCLUDE;
         EOE_ip_uint32_to_byte(&nic_ports[port_ix].dns_ip,
               &eoembx->data[data_offset]);
         /* 增加uint32 IP地址的大小 */
         data_offset += EOE_IP4_LENGTH;
      }

      /* 在获取IP请求中包含DNS名称 */
      if(nic_ports[port_ix].dns_name_set)
      {
         /* TwinCAT 包含EOE_DNS_NAME_LENGTH个字符，即使名称更短 */
         flags |= EOE_PARAM_DNS_NAME_INCLUDE;
         memcpy(&eoembx->data[data_offset],
               nic_ports[port_ix].dns_name,
               EOE_DNS_NAME_LENGTH);
         /* 增加DNS名称长度的大小 */
         data_offset += EOE_DNS_NAME_LENGTH;
      }

      eoembx->data[0] = flags;
      eoembx->mbxheader.length = htoes (ESC_EOEHSIZE + data_offset);
   }
}

/** EoE设置IP参数请求处理器。将发送设置IP参数响应。
 */
static void EOE_set_ip (void)
{
   _EOE *eoembx;
   uint32_t eoedatasize, data_offset;
   uint16_t frameinfo1;
   uint8_t port;
   uint8_t  flags;
   uint16_t result;
   int port_ix;

   eoembx = (_EOE *) &MBX[0];
   eoedatasize = etohs(eoembx->mbxheader.length) - ESC_EOEHSIZE;
   frameinfo1 = etohs(eoembx->eoeheader.frameinfo1);
   port = EOE_HDR_FRAME_PORT_GET(frameinfo1);
   flags = eoembx->data[0];
   data_offset = EOE_PARAM_OFFSET;

   if(port  > EOE_NUMBER_OF_PORTS)
   {
      DPRINT("无效的端口\n");
      /* 返回给定端口的错误响应 */
      frameinfo1 = EOE_HDR_FRAME_PORT_SET(port);
      frameinfo1 |= EOE_INIT_RESP;
      frameinfo1 |= EOE_HDR_LAST_FRAGMENT;
      EOE_no_data_response(frameinfo1, EOE_RESULT_UNSPECIFIED_ERROR);
      return;
   }

   /* 在设置IP请求中包含MAC？ */
   port_ix = EOE_PORT_INDEX(port);
   if(flags & EOE_PARAM_MAC_INCLUDE)
   {
      memcpy(&nic_ports[port_ix].mac.addr,
            &eoembx->data[data_offset],
            EOE_ETHADDR_LENGTH);
      nic_ports[port_ix].mac_set = 1;
      /* 增加MAC地址的大小 */
      data_offset += EOE_ETHADDR_LENGTH;
   }
   /* 在设置IP请求中包含IP？ */
   if(flags & EOE_PARAM_IP_INCLUDE)
   {
      EOE_ip_byte_to_uint32(&eoembx->data[data_offset],
            &nic_ports[port_ix].ip);
      nic_ports[port_ix].ip_set = 1;
      /* 增加uint32 IP地址的大小 */
      data_offset += EOE_IP4_LENGTH;
   }
   /* 在设置IP请求中包含子网？ */
   if(flags & EOE_PARAM_SUBNET_IP_INCLUDE)
   {
      EOE_ip_byte_to_uint32(&eoembx->data[data_offset],
            &nic_ports[port_ix].subnet);
      nic_ports[port_ix].subnet_set = 1;
      /* 增加uint32 IP地址的大小 */
      data_offset += EOE_IP4_LENGTH;
   }
   /* 在设置IP请求中包含默认网关？ */
   if(flags & EOE_PARAM_DEFAULT_GATEWAY_INCLUDE)
   {
      EOE_ip_byte_to_uint32(&eoembx->data[data_offset],
            &nic_ports[port_ix].default_gateway);
      nic_ports[port_ix].default_gateway_set = 1;
      /* 增加uint32 IP地址的大小 */
      data_offset += EOE_IP4_LENGTH;
   }
   /* 在设置IP请求中包含DNS IP？ */
   if(flags & EOE_PARAM_DNS_IP_INCLUDE)
   {
      EOE_ip_byte_to_uint32(&eoembx->data[data_offset],
            &nic_ports[port_ix].dns_ip);
      nic_ports[port_ix].dns_ip_set = 1;
      /* 增加uint32 IP地址的大小 */
      data_offset += EOE_IP4_LENGTH;
   }
   /* 在设置IP请求中包含DNS名称？ */
   if(flags & EOE_PARAM_DNS_NAME_INCLUDE)
   {
      uint32_t dns_len = MIN((eoedatasize - data_offset), EOE_DNS_NAME_LENGTH);
      memcpy(nic_ports[port_ix].dns_name,
            &eoembx->data[data_offset],
            dns_len);
      nic_ports[port_ix].dns_name_set = 1;
      data_offset += dns_len; /* 期望1-EOE_DNS_NAME_LENGTH; */
   }

   if(data_offset > eoedatasize)
   {
      result = MBXERR_SIZETOOSHORT;
   }
   else
   {
      /* 应用程序特定的存储设置函数。通常在这里
       * 设置TCP/IP栈的IP */
      if(eoe_cfg->store_ethernet_settings != NULL)
      {
         result = (uint16_t)eoe_cfg->store_ethernet_settings();
      }
      else
      {
         result = EOE_RESULT_NO_IP_SUPPORT;
      }
   }
   frameinfo1 = EOE_HDR_FRAME_PORT_SET(port);
   frameinfo1 |= EOE_INIT_RESP;
   frameinfo1 |= EOE_HDR_LAST_FRAGMENT;
   EOE_no_data_response(frameinfo1, result);
}


/** EoE接收片段处理器。
 */
static void EOE_receive_fragment (void)
{
   _EOE *eoembx;
   eoembx = (_EOE *) &MBX[0];
   uint32_t eoedatasize = etohs(eoembx->mbxheader.length) - ESC_EOEHSIZE;
   uint16_t frameinfo1 = etohs(eoembx->eoeheader.frameinfo1);
   uint16_t frameinfo2 = etohs(eoembx->eoeheader.frameinfo2);

   /* 捕获错误情况 */
   if(EOEvar.rxfragmentno != EOE_HDR_FRAG_NO_GET(frameinfo2))
   {
      DPRINT("意外的片段编号 %"PRIu32"，期望: %"PRIu32"\n",
            EOE_HDR_FRAG_NO_GET(frameinfo2), EOEvar.rxfragmentno);
      /* 清理现有保存的数据 */
      if(EOEvar.rxfragmentno != 0)
      {
         EOE_init_rx();
      }
      /* 如果不是新帧的开始，则跳过片段 */
      if(EOE_HDR_FRAG_NO_GET(frameinfo2) > 0)
      {
         return;
      }
   }

   /* 在片段0开始新帧 */
   if(EOEvar.rxfragmentno == 0)
   {
      EOEvar.rxframesize = (EOE_HDR_FRAME_OFFSET_GET(frameinfo2) << 5);

      if(EOEvar.rxebuf.payload != NULL)
      {
         EOEvar.rxebuf.len = EOEvar.rxframesize;
         EOEvar.rxframeoffset = 0;
         EOEvar.rxframeno = EOE_HDR_FRAME_NO_GET(frameinfo2);
      }
      else
      {
         DPRINT("接收 lwip buffer无效\n");
         EOE_init_rx ();
         return;
      }
   }
   /* 在帧中接收到片段 */
   else
   {
      uint32_t offset = (EOE_HDR_FRAME_OFFSET_GET(frameinfo2) << 5);
      /* 验证接收到的片段 */
      if(EOEvar.rxframeno != EOE_HDR_FRAME_NO_GET(frameinfo2))
      {
         DPRINT("意外的帧编号 %"PRIu32"，期望: %"PRIu32"\n",
               EOE_HDR_FRAME_NO_GET(frameinfo2), EOEvar.rxframeno);
         EOE_init_rx ();
         return;
      }
      else if(EOEvar.rxframeoffset != offset)
      {
         DPRINT("意外的帧偏移 %"PRIu32"，期望: %"PRIu32"\n",
               offset, EOEvar.rxframeoffset);
         EOE_init_rx ();
         return;
      }
   }

   /* 检查分配的 lwip buffer是否足够 */
   if ((EOEvar.rxframeoffset + eoedatasize) <= EOEvar.rxframesize)
   {
      memcpy((uint8_t *)(EOEvar.rxebuf.payload + EOEvar.rxframeoffset),
            eoembx->data,
            eoedatasize);
      EOEvar.rxframeoffset += eoedatasize;
      EOEvar.rxfragmentno++;
   }
   else
   {
      DPRINT("数据大小超过可用 lwip buffer大小\n");
      EOE_init_rx ();
      return;
   }

   if(EOE_HDR_LAST_FRAGMENT_GET(frameinfo1))
   {
      /* 移除时间戳，TODO: 支持时间戳？ */
      if(EOE_HDR_TIME_APPEND_GET(frameinfo1))
      {
         EOEvar.rxframeoffset -= 4U;
      }
      EOEvar.rxebuf.len =  EOEvar.rxframeoffset;
      eoe_cfg->handle_recv_buffer(EOE_HDR_FRAME_PORT_GET(frameinfo1),
            &EOEvar.rxebuf);
      /* 将 lwip buffer的所有权传递给接收函数 */
      EOEvar.rxebuf.payload = NULL;
      EOE_init_rx ();
   }
}

/** EoE发送片段处理器。
 */
static void EOE_send_fragment ()
{
   _EOE *eoembx;
   uint8_t mbxhandle;
   int len;
   uint32_t len_to_send;
   uint16_t frameinfo1;
   uint16_t frameinfo2;
   static uint8_t frameno = 0;

   /* 我们是否有当前的传输正在进行 */
   if(EOEvar.txebuf.payload == NULL)
   {
      /* 如果可用，获取一个 lwip buffer */
      len = eoe_cfg->fetch_send_buffer(0, &EOEvar.txebuf);
      if(len > 0)
      {
         EOEvar.txframesize = (uint32_t)len;
      }
      else
      {
         return;
      }
   }

   /* 如果可以获取一个空闲邮箱，则处理帧 */
   mbxhandle = ESC_claimbuffer ();
   if (mbxhandle)
   {
      len_to_send = (EOEvar.txframesize - EOEvar.txframeoffset);
      if((len_to_send + ESC_EOEHSIZE + ESC_MBXHSIZE) > ESC_MBXSIZE)
      {
         /* 调整为整个32字节块的长度以符合规范 */
         len_to_send =
               (((ESC_MBXSIZE - ESC_EOEHSIZE - ESC_MBXHSIZE) >> 5) << 5);
      }

      /* TODO: 端口处理？ */
      if(len_to_send == (EOEvar.txframesize - EOEvar.txframeoffset))
      {
         frameinfo1 = EOE_HDR_LAST_FRAGMENT_SET(1);
      }
      else
      {
         frameinfo1 = 0;
      }

      uint16_t tempframe2;
      /* 设置片段编号 */
      frameinfo2 = EOE_HDR_FRAG_NO_SET(EOEvar.txfragmentno);

      /* 设置片段0的完整大小或帧内片段的偏移 */
      if(EOEvar.txfragmentno > 0)
      {
         tempframe2 = EOE_HDR_FRAME_OFFSET_SET((EOEvar.txframeoffset >> 5));
         frameinfo2 |= tempframe2;
      }
      else
      {
         tempframe2 = EOE_HDR_FRAME_OFFSET_SET(((EOEvar.txframesize + 31) >> 5));
         frameinfo2 |= tempframe2;
         frameno++;
      }

      /* 设置帧编号 */
      tempframe2 = EOE_HDR_FRAME_NO_SET(frameno);
      frameinfo2 |= tempframe2;

      eoembx = (_EOE *) &MBX[mbxhandle * ESC_MBXSIZE];
      eoembx->mbxheader.length = htoes (len_to_send + ESC_EOEHSIZE);
      eoembx->mbxheader.mbxtype = MBXEOE;
      eoembx->eoeheader.frameinfo1 = htoes(frameinfo1);
      eoembx->eoeheader.frameinfo2 = htoes(frameinfo2);

      /* 将数据复制到邮箱 */
      memcpy(eoembx->data,
            &EOEvar.txebuf.payload[EOEvar.txframeoffset],
            len_to_send);
      MBXcontrol[mbxhandle].state = MBXstate_outreq;

      /* 我们是否完成了帧？ */
      if(len_to_send == (EOEvar.txframesize - EOEvar.txframeoffset))
      {
         EOE_init_tx ();
      }
      else
      {
         EOEvar.txframeoffset += len_to_send;
         EOEvar.txfragmentno++;
      }
      if(eoe_cfg->fragment_sent_event != NULL)
      {
         eoe_cfg->fragment_sent_event();
      }
   }
}

/** 初始化，通过清除所有当前状态变量并获取新 lwip buffer。
 */
static void EOE_init_rx ()
{
   /* 重置RX传输状态变量 */
   EOEvar.rxfragmentno = 0;
   EOEvar.rxframesize = 0;
   EOEvar.rxframeoffset = 0;
   EOEvar.rxframeno = 0;

   /* 获取 lwip buffer */
   if(EOEvar.rxebuf.payload == NULL)
   {
      if(eoe_cfg->get_buffer != NULL)
      {
         /* TODO: 验证大小与 lwip buffer大小 */
         eoe_cfg->get_buffer(&EOEvar.rxebuf);
      }
   }
}

/** 初始化，通过清除所有当前状态变量并释放旧 lwip buffer。
 */
static void EOE_init_tx ()
{
   /* 重置TX传输状态变量 */
   EOEvar.txfragmentno = 0;
   EOEvar.txframesize = 0;
   EOEvar.txframeoffset = 0;

   /* 释放看似被遗弃的 lwip buffer */
   if((EOEvar.txebuf.payload != NULL))
   {
      if(eoe_cfg->free_buffer != NULL)
      {
         eoe_cfg->free_buffer(&EOEvar.txebuf);
         EOEvar.txebuf.pbuf = NULL;
         EOEvar.txebuf.payload = NULL;
         EOEvar.txebuf.len = 0;
      }
   }
}

/** 初始化，通过清除所有当前状态变量。
 */
void EOE_init ()
{
   DPRINT("EOE_init\n");
   EOE_init_tx ();
   EOE_init_rx ();
}

/** 将应用程序配置变量复制到EoE模块本地指针变量的函数
 *
 * @param[in] cfg       = 指向由应用程序静态声明的配置变量的指针
 *                      ，持有特定于应用程序的详细信息。
 */
void EOE_config (eoe_cfg_t * cfg)
{
   eoe_cfg = cfg;
}

/** 主EoE接收函数，检查当前邮箱缓冲区的状态
 * 承载数据，将邮箱分配给适当的EoE函数
 * 取决于请求的帧类型。
 */
void ESC_eoeprocess (void)
{
   _MBXh *mbh;
   _EOE *eoembx;
   uint16_t frameinfo1;

   if (ESCvar.MBXrun == 0)
   {
      return;
   }
   if (!ESCvar.xoe && (MBXcontrol[0].state == MBXstate_inclaim))
   {
      mbh = (_MBXh *) &MBX[0];
      if (mbh->mbxtype == MBXEOE)
      {
         ESCvar.xoe = MBXEOE;
      }
   }
   if (ESCvar.xoe == MBXEOE)
   {
      eoembx = (_EOE *) &MBX[0];
      /* 验证文件数据的大小。 */
      if (etohs (eoembx->mbxheader.length) < ESC_EOEHSIZE)
      {
         EOE_no_data_response (
               EOE_INIT_RESP | EOE_HDR_LAST_FRAGMENT,
               MBXERR_SIZETOOSHORT);
      }
      else
      {
         frameinfo1 = etohs(eoembx->eoeheader.frameinfo1);
         switch (EOE_HDR_FRAME_TYPE_GET(frameinfo1))
         {
            case EOE_FRAG_DATA:
            {
               EOE_receive_fragment ();
               break;
            }
            case EOE_INIT_REQ:
            {
               EOE_set_ip ();
               break;
            }
            case EOE_GET_IP_PARAM_REQ:
            {
               EOE_get_ip ();
               break;
            }
            case EOE_INIT_RESP_TIMESTAMP:
            case EOE_INIT_RESP:
            case EOE_SET_ADDR_FILTER_REQ:
            case EOE_SET_ADDR_FILTER_RESP:
            case EOE_GET_IP_PARAM_RESP:
            case EOE_GET_ADDR_FILTER_REQ:
            case EOE_GET_ADDR_FILTER_RESP:
            default:
            {
               DPRINT("EOE_RESULT_UNSUPPORTED_TYPE\n");
               EOE_no_data_response ((EOE_HDR_FRAME_PORT & frameinfo1) |
                     (EOE_HDR_FRAME_TYPE & frameinfo1) |
                     EOE_HDR_LAST_FRAGMENT,
                     EOE_RESULT_UNSUPPORTED_FRAME_TYPE);
               break;
            }
         }
      }
      MBXcontrol[0].state = MBXstate_idle;
      ESCvar.xoe = 0;
   }
}

/** EoE发送片段的函数。
 * 注意：不线程安全，应从SOES任务中顺序调用
 * 与其他邮箱函数一起。通过添加
 * 线程安全的应用程序获取函数来添加对线程的支持，例如一个带缓冲区的邮箱
 * 由TCP/IP栈发布，由SOES任务获取。
 */
void ESC_eoeprocess_tx (void)
{
   if (ESCvar.MBXrun == 0)
   {
      return;
   }
   EOE_send_fragment ();
}

