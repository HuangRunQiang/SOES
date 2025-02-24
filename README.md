简单开源EtherCAT从站
====
[![构建状态](https://github.com/OpenEtherCATsociety/SOES/workflows/build/badge.svg?branch=master)](https://github.com/OpenEtherCATsociety/SOES/actions?workflow=build)

SOES（简单开源EtherCAT从站栈）是一个开源从站栈，使用非常简单，且占用空间小。它是市场上更复杂的栈的良好替代品。

概述
----
SOES是一个用C语言编写的EtherCAT从站栈。它的目的是用于学习和使用。所有用户都被邀请研究源代码，以了解EtherCAT从站的工作原理。

功能列表：
 - 基于地址偏移的硬件抽象层（HAL），通过任何接口轻松进行ESC读/写访问
 - 带数据链路层的邮箱
 - CoE（对象字典）
 - 对象字典
 - 支持所有尺寸的SDO读写，包括分段传输
 - 适合嵌入式应用的易于移植的C代码
 - 固定和/或动态PDO映射
 - 带引导模板的FoE
 - 支持小端和大端目标
 - 运行轮询、混合轮询/中断或中断模式
 - 支持SM同步
 - 支持DC sync0和DC同步
 - 通过新的配置参数添加栈配置到/从“stack”_init
 - EoE（以太网对象嵌入）

待办事项
 - 更新文档
 - 添加EoE示例应用程序
