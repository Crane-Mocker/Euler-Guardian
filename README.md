# Euler Guardian

Euler Guardian: 操作系统风险评估系统

gitee 地址：
https://gitee.com/openeuler-competition/summer2021-110

gitlab 地址：


<!-- vim-markdown-toc GFM -->

* [配色](#配色)
* [front end 前端](#front-end-前端)
* [模块说明](#模块说明)
	* [local scan 本地扫描模块](#local-scan-本地扫描模块)
		* [PreOp 预操作](#preop-预操作)
		* [SysInfoChk 系统信息检查](#sysinfochk-系统信息检查)
		* [SecCheck 安全策略检查](#seccheck-安全策略检查)
		* [UserInfoChk 用户信息检查](#userinfochk-用户信息检查)
		* [FilePermChk 文件权限检查](#filepermchk-文件权限检查)
		* [OVALChk 软件包版本漏洞检查](#ovalchk-软件包版本漏洞检查)
		* [Function 函数调用](#function-函数调用)
	* [ER emergency response 应急响应模块](#er-emergency-response-应急响应模块)
		* [BasicCheck](#basiccheck)
		* [SensitiveFileCheck](#sensitivefilecheck)
		* [FilesChanged](#fileschanged)
		* [ProcAnalyse](#procanalyse)
		* [HiddenProc](#hiddenproc)
		* [HistoryCheck](#historycheck)
		* [UserAnalyse](#useranalyse)
		* [CronCheck](#croncheck)
		* [WebshellCheck](#webshellcheck)

<!-- vim-markdown-toc -->

## 配色

|color|info|
|---|---|
|blue| process display|
|default|information display|
|green|normal|
|yellow|low risk|
|red|high risk|
|purple|suggesion to repair|

## front end 前端

初始化CSS来自：
https://necolas.github.io/normalize.css/8.0.1/normalize.css

## 模块说明

### local scan 本地扫描模块

#### PreOp 预操作

1. 检查current id, 判断是否有root权限

2. 检查SetUID, 获得pwd

3. 检查是否有之前检查留下的文件，若有，则删除

#### SysInfoChk 系统信息检查

检查系统信息。

检查内核信息并输出，包括内核版本, 编译使用的gcc版本，编译的时间和release信息。

#### SecCheck 安全策略检查

检查是否开启了SELinux, 检查资源的限制情况, 检查口令安全策略

#### UserInfoChk 用户信息检查

检查用户信息。

检查hostname和id, 检查口令是否以hash存储，检查上一次登录的用户。

#### FilePermChk 文件权限检查

查找系统中所有含s权限的文件。

查找无属组的777权限文件。

查找孤儿文件。

查找指定目录下文件的权限, 默认rwxrwxrwx权限。（文件权限的检查和用户的需求有很大关系。）

#### OVALChk 软件包版本漏洞检查

利用OVAL，根据软件包版本检查是否存在CVE漏洞。

#### Function 函数调用

调用函数。

### ER emergency response 应急响应模块

使用场景: Linux受到入侵后的自动化快速应急响应。

#### BasicCheck

基本检查

![ER-0](pic/ER-0.png)

1. iptables防火墙规则

2. 开放的TCP, UDP端口

- systemd-resolve
systemd-resolve 是 Ubuntu 下 DNS 解析相关的命令，能使用它来操作 DNS 相关的功能。
- avahi
Zero configuration networking(zeroconf)零配置网络服务规范，是一种用于自动生成可用IP地址的网络技术，不需要额外的手动配置和专属的配置服务器。
Avahi 是Zeroconf规范的开源实现，常见使用在Linux上。包含了一整套多播DNS(multicastDNS)/DNS-SD网络服务的实现。

3. init.d services

4. `$PATH`

#### SensitiveFileCheck

敏感文件检查

![ER-1](pic/ER-1.png)

1. 检查加载到内核的不常见module

tmpArr[]:

|0|1|2|
|---|---|---|
|Module|Size|Used by|

#### FilesChanged

被改变的文件检查

![ER-2](pic/ER-2.png)

1. 文件打开，但是文件已被删除(除浏览器)

tmpArr[]

|0|1|2|3|4|5|6|7|8|9|
|---|---|---|---|---|---|---|---|---|---|
|COMMAND|PID|USER|FD|TYPE|DEVICE|SIZE/OFF|NLINK|NODE|NAME|


2. 文件改变时间检查

检查7天之内，指定目录下ctime改变

- atime: access time, 在读取文件或者执行文件时更改的
- ctime: change time, 在写入文件、更改所有者、权限或链接设置时随Inode内容更改而更改
- mtime：modify time, 写入文件时更改

#### ProcAnalyse

进程检查

![ER-3](pic/ER-3.png)

检查proc使用CPU的百分比是否多于n%

#### HiddenProc

检查隐藏的process, 并按升序排序

#### HistoryCheck

![ER-4](pic/ER-4.png)

1. 检查history中wget

2. 检查history中ssh

3. 检查是否有ssh的root用户口令爆破

#### UserAnalyse

![ER-5](pic/ER-5.png)

1. 检查有root权限的用户是否为root

2. 检查空口令用户

3. 可登陆用户

4. 所有用户的上次登录情况

#### CronCheck

![ER-6](pic/ER-6.png)

1. root的crontab files检查

2. cron后门检查

#### WebshellCheck

![ER-7](pic/ER-7.png)

基于文件的webshell检查, 支持php asp jsp

## Reference

- [Lynis](https://cisofy.com/documentation/lynis/)
- [Vulmap](https://github.com/vulmon/Vulmap)
- [Nix Auditor](https://github.com/XalfiE/Nix-Auditor)
- [GScan](https://github.com/grayddq/GScan)
- wooyun: Linux服务器应急事件溯源报告
- 黑客入侵应急分析手工排查
- 安恒: 勒索病毒应急与响应手册
- 绿盟: 应急响应技术指南
- 等保2.0: GBT25070-2019信息安全技术网络安全等级保护安全设计技术要求
