/*
 * 根据GNU通用公共许可证第2版及其附加条款进行许可。有关完整的许可证信息，请参见项目根目录中的LICENSE文件。
 */
#include <stddef.h>
#include "esc.h"
#include "esc_coe.h"
#include "esc_foe.h"
#include "esc_eoe.h"
#include "ecat_slv.h"

#define IS_RXPDO(index) ((index) >= 0x1600 && (index) < 0x1800) // 判断是否为接收PDO
#define IS_TXPDO(index) ((index) >= 0x1A00 && (index) < 0x1C00) // 判断是否为发送PDO

/* 栈使用的全局变量 */
uint8_t     MBX[MBXBUFFERS * MAX(MBXSIZE, MBXSIZEBOOT)]; // 邮箱缓冲区
_MBXcontrol MBXcontrol[MBXBUFFERS]; // 邮箱控制结构
_SMmap      SMmap2[MAX_MAPPINGS_SM2]; // SM2映射
_SMmap      SMmap3[MAX_MAPPINGS_SM3]; // SM3映射
_ESCvar     ESCvar; // ESC变量

/* 私有变量 */
static volatile int watchdog; // 看门狗计数器

#if MAX_MAPPINGS_SM2 > 0
static uint8_t rxpdo[MAX_RXPDO_SIZE] __attribute__((aligned (8))); // 接收PDO缓冲区
#else
extern uint8_t rxpdo[]; // 外部接收PDO缓冲区
#endif

#if MAX_MAPPINGS_SM3 > 0
static uint8_t txpdo[MAX_TXPDO_SIZE] __attribute__((aligned (8))); // 发送PDO缓冲区
#else
extern uint8_t txpdo[]; // 外部发送PDO缓冲区
#endif

/** 
 * 函数用于预处理传入的SDO下载请求。
 *
 * @param[in] index      = 要检查的SDO下载请求的索引
 * @param[in] subindex   = 要检查的SDO下载请求的子索引
 * @return SDO中止代码，成功时返回0
 */
uint32_t ESC_download_pre_objecthandler (uint16_t index,
      uint8_t subindex,
      void * data,
      size_t size,
      uint16_t flags)
{
   if (IS_RXPDO (index) ||
       IS_TXPDO (index) ||
       index == RX_PDO_OBJIDX ||
       index == TX_PDO_OBJIDX)
   {
      uint8_t minSub = ((flags & COMPLETE_ACCESS_FLAG) == 0) ? 0 : 1;
      if (subindex > minSub && COE_maxSub (index) != 0)
      {
         return ABORT_SUBINDEX0_NOT_ZERO; // 子索引不为零的中止代码
      }
   }

   if (ESCvar.pre_object_download_hook)
   {
      return (ESCvar.pre_object_download_hook) (index,
            subindex,
            data,
            size,
            flags); // 调用用户定义的预处理钩子
   }

   return 0; // 成功
}

/** 
 * 从从站栈SDO下载处理程序调用的钩子，用于处理用户指定的索引和子索引。
 *
 * @param[in] index      = 要处理的SDO下载请求的索引
 * @param[in] subindex   = 要处理的SDO下载请求的子索引
 * @return SDO中止代码，成功时返回0
 */
uint32_t ESC_download_post_objecthandler (uint16_t index, uint8_t subindex, uint16_t flags)
{
   if (ESCvar.post_object_download_hook != NULL)
   {
      return (ESCvar.post_object_download_hook)(index, subindex, flags); // 调用用户定义的后处理钩子
   }

   return 0; // 成功
}

/** 
 * 函数用于预处理传入的SDO上传请求。
 *
 * @param[in] index      = 要处理的SDO上传请求的索引
 * @param[in] subindex   = 要处理的SDO上传请求的子索引
 * @return SDO中止代码，成功时返回0
 */
uint32_t ESC_upload_pre_objecthandler (uint16_t index,
      uint8_t subindex,
      void * data,
      size_t *size,
      uint16_t flags)
{
   if (ESCvar.pre_object_upload_hook != NULL)
   {
      return (ESCvar.pre_object_upload_hook) (index,
            subindex,
            data,
            size,
            flags); // 调用用户定义的预处理钩子
   }

   return 0; // 成功
}

/** 
 * 从从站栈SDO上传处理程序调用的钩子，用于处理用户指定的索引和子索引。
 *
 * @param[in] index      = 要处理的SDO上传请求的索引
 * @param[in] subindex   = 要处理的SDO上传请求的子索引
 * @return SDO中止代码，成功时返回0
 */
uint32_t ESC_upload_post_objecthandler (uint16_t index, uint8_t subindex, uint16_t flags)
{
   if (ESCvar.post_object_upload_hook != NULL)
   {
      return (ESCvar.post_object_upload_hook)(index, subindex, flags); // 调用用户定义的后处理钩子
   }

   return 0; // 成功
}

/** 
 * 从从站栈ESC_stopoutputs调用的钩子，用于处理状态变化
 * 强制我们停止输出。在这里我们可以将它们设置为安全状态。
 */
void APP_safeoutput (void)
{
   DPRINT ("APP_safeoutput\n");

   if(ESCvar.safeoutput_override != NULL)
   {
      (ESCvar.safeoutput_override)(); // 调用用户定义的安全输出钩子
   }
}

/** 
 * 将本地进程数据写入同步管理器3，主输入。
 */
void TXPDO_update (void)
{
   if(ESCvar.txpdo_override != NULL)
   {
      (ESCvar.txpdo_override)(); // 调用用户定义的发送PDO钩子
   }
   else
   {
      if (MAX_MAPPINGS_SM3 > 0)
      {
         COE_pdoPack (txpdo, ESCvar.sm3mappings, SMmap3); // 打包发送PDO
      }
      ESC_write (ESC_SM3_sma, txpdo, ESCvar.ESC_SM3_sml); // 写入发送PDO
   }
}

/** 
 * 从同步管理器2读取本地进程数据，主输出。
 */
void RXPDO_update (void)
{
   if(ESCvar.rxpdo_override != NULL)
   {
      (ESCvar.rxpdo_override)(); // 调用用户定义的接收PDO钩子
   }
   else
   {
      ESC_read (ESC_SM2_sma, rxpdo, ESCvar.ESC_SM2_sml); // 读取接收PDO
      if (MAX_MAPPINGS_SM2 > 0)
      {
         COE_pdoUnpack (rxpdo, ESCvar.sm2mappings, SMmap2); // 解包接收PDO
      }
   }
}

/* 设置看门狗计数值，当使用硬件看门狗0x4xx时没有任何影响
 *
 * @param[in] watchdogcnt  = 新的看门狗计数值
 */
void APP_setwatchdog (int watchdogcnt)
{
   CC_ATOMIC_SET(ESCvar.watchdogcnt, watchdogcnt); // 设置看门狗计数
}

/* 
 * 函数用于更新本地I/O，调用读取EtherCAT输出，调用
 * 写入EtherCAT输入。实现看门狗计数器以计算超时，如果我们
 * 进行了影响App.state的状态更改。
 */
void DIG_process (uint8_t flags)
{
   /* 处理看门狗 */
   if((flags & DIG_PROCESS_WD_FLAG) > 0)
   {
      if (CC_ATOMIC_GET(watchdog) > 0)
      {
         CC_ATOMIC_SUB(watchdog, 1); // 减少看门狗计数
      }

      if ((CC_ATOMIC_GET(watchdog) <= 0) &&
          ((CC_ATOMIC_GET(ESCvar.App.state) & APPSTATE_OUTPUT) > 0) &&
           (ESCvar.ESC_SM2_sml > 0))
      {
         DPRINT("DIG_process watchdog expired\n");
         ESC_ALstatusgotoerror((ESCsafeop | ESCerror), ALERR_WATCHDOG); // 看门狗超时，进入错误状态
      }
      else if(((CC_ATOMIC_GET(ESCvar.App.state) & APPSTATE_OUTPUT) == 0))
      {
         CC_ATOMIC_SET(watchdog, ESCvar.watchdogcnt); // 重置看门狗计数
      }
   }

   /* 处理输出 */
   if ((flags & DIG_PROCESS_OUTPUTS_FLAG) > 0)
   {
      if(((CC_ATOMIC_GET(ESCvar.App.state) & APPSTATE_OUTPUT) > 0) &&
         (ESCvar.ALevent & ESCREG_ALEVENT_SM2))
      {
         RXPDO_update(); // 更新接收PDO
         CC_ATOMIC_SET(watchdog, ESCvar.watchdogcnt); // 重置看门狗计数
         /* 设置输出 */
         cb_set_outputs();
      }
      else if (ESCvar.ALevent & ESCREG_ALEVENT_SM2)
      {
         ESC_read (ESC_SM2_sma, rxpdo, ESCvar.ESC_SM2_sml); // 读取接收PDO
      }
   }

   /* 调用应用程序 */
   if ((flags & DIG_PROCESS_APP_HOOK_FLAG) > 0)
   {
      /* 如果设置了回调，调用应用程序回调 */
      if (ESCvar.application_hook != NULL)
      {
         (ESCvar.application_hook)();
      }
   }

   /* 处理输入 */
   if ((flags & DIG_PROCESS_INPUTS_FLAG) > 0)
   {
      if(CC_ATOMIC_GET(ESCvar.App.state) > 0)
      {
         /* 更新输入 */
         cb_get_inputs();
         TXPDO_update(); // 更新发送PDO
      }
   }
}

/*
 * SM变化的处理程序，SM0/1、AL控制和EEPROM事件，应用程序
 * 控制应服务和重新激活的中断，使用事件掩码参数
 */
void ecat_slv_worker (uint32_t event_mask)
{
   do
   {
      /* 检查状态机 */
      ESC_state();
      /* 检查SM激活事件 */
      ESC_sm_act_event();

      /* 检查邮箱 */
      while ((ESC_mbxprocess() > 0) || (ESCvar.txcue > 0))
      {
         ESC_coeprocess(); // 处理COE
#if USE_FOE
         ESC_foeprocess(); // 处理FoE
#endif
#if USE_EOE
         ESC_eoeprocess(); // 处理EoE
#endif
         ESC_xoeprocess(); // 处理XoE
      }
#if USE_EOE
      ESC_eoeprocess_tx(); // 处理EoE发送
#endif
      /* 如果设置了，调用模拟EEPROM处理程序 */
      if (ESCvar.esc_hw_eep_handler != NULL)
      {
         (ESCvar.esc_hw_eep_handler)();
      }

      CC_ATOMIC_SET(ESCvar.ALevent, ESC_ALeventread()); // 读取AL事件

   } while(ESCvar.ALevent & event_mask); // 处理事件掩码中的事件

   ESC_ALeventmaskwrite(ESC_ALeventmaskread() | event_mask); // 写入事件掩码
}

/*
 * 轮询函数。它应该定期调用应用程序
 * 当仅SM2/DC中断处于活动状态时。
 * 读取和处理EtherCAT状态、状态、邮箱和EEPROM的事件。
 */
void ecat_slv_poll (void)
{
   /* 从ESC读取本地时间 */
   ESC_read (ESCREG_LOCALTIME, (void *) &ESCvar.Time, sizeof (ESCvar.Time));
   ESCvar.Time = etohl (ESCvar.Time); // 转换本地时间

   /* 检查状态机 */
   ESC_state();
   /* 检查SM激活事件 */
   ESC_sm_act_event();

   /* 检查邮箱 */
   if (ESC_mbxprocess())
   {
      ESC_coeprocess(); // 处理COE
#if USE_FOE
      ESC_foeprocess(); // 处理FoE
#endif
#if USE_EOE
      ESC_eoeprocess(); // 处理EoE
#endif
      ESC_xoeprocess(); // 处理XoE
   }
#if USE_EOE
   ESC_eoeprocess_tx(); // 处理EoE发送
#endif

   /* 如果设置了，调用模拟EEPROM处理程序 */
   if (ESCvar.esc_hw_eep_handler != NULL)
   {
      (ESCvar.esc_hw_eep_handler)();
   }
}

/*
 * 在自由运行应用程序中轮询所有事件
 */
void ecat_slv (void)
{
   ecat_slv_poll(); // 轮询事件
   DIG_process(DIG_PROCESS_WD_FLAG | DIG_PROCESS_OUTPUTS_FLAG |
         DIG_PROCESS_APP_HOOK_FLAG | DIG_PROCESS_INPUTS_FLAG); // 处理数字输入输出
}

/*
 * 初始化从站栈。
 */
void ecat_slv_init (esc_cfg_t * config)
{
   DPRINT ("从站栈初始化开始\n");

   /* 初始化看门狗 */
   watchdog = config->watchdog_cnt;

   /* 调用栈配置 */
   ESC_config (config);
   /* 调用硬件初始化 */
   ESC_init (config);

   /* 等待ESC启动 */
   while ((ESCvar.DLstatus & 0x0001) == 0)
   {
      ESC_read (ESCREG_DLSTATUS, (void *) &ESCvar.DLstatus,
                sizeof (ESCvar.DLstatus)); // 读取DL状态
      ESCvar.DLstatus = etohs (ESCvar.DLstatus); // 转换DL状态
   }

#if USE_FOE
   /* 初始化FoE */
   FOE_init ();
#endif

#if USE_EOE
   /* 初始化EoE */
   EOE_init ();
#endif

   /* 将ESC重置为初始化状态 */
   ESC_ALstatus (ESCinit);
   ESC_ALerror (ALERR_NONE); // 清除错误
   ESC_stopmbx (); // 停止邮箱
   ESC_stopinput (); // 停止输入
   ESC_stopoutput (); // 停止输出
   /* 初始化对象字典默认值 */
   COE_initDefaultValues ();
}
