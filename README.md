# Euler Guardian

Euler Guardian: 操作系统风险评估系统

gitee 地址：
https://gitee.com/openeuler-competition/summer2021-110

gitlab 地址：


<!-- vim-markdown-toc GFM -->

* [配色](#配色)
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
		* [基本检查](#基本检查)
		* [文件检查](#文件检查)
		* [进程检查](#进程检查)
		* [history和log检查](#history和log检查)
		* [webshell检查](#webshell检查)

<!-- vim-markdown-toc -->

## 配色

|info|value|color|
|---|---|---|
|display output| \e[1;34m | bold blue|
|| \e[0;34m | blue|
|| \e[1;32m | bold green|
|normal output info | \e[00m | default |
|fail | \e[0;36m | cyan|


|color|info|
|---|---|
|blue| process display|
|default|information display|
|green|normal|
|yellow|low risk|
|red|high risk|
|purple|suggesion to repair|
## css

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

详见代码注释

#### 基本检查

`/tmp`下文件 `init.d`下services, `$PATH`

#### 文件检查

输入文件类型、指定目录，检查该目录下24h改变过的/有777权限的该类型文件

输入时间、指定目录，检查该目录下该时间改变过的文件

#### 进程检查

检查proc使用CPU的百分比。多余n%->低危

输入PID, 查看详情

检查隐藏的process

#### HistoryCheck

检查history中wget
检查history中ssh
ssh root登录失败>50 -> ip可能为爆破ssh的IP

#### webshell检查

基于文件的webshell检查, 支持php asp jsp

#### UserAnalyse

提示信息+输出(是否危险)+修复建议

检查有root权限的用户，若不为root->高危。
检查空口令用户->高危。
