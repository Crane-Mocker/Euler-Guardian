# Euler Guardian

Euler Guardian: 操作系统风险评估系统

gitee 地址：
https://gitee.com/openeuler-competition/summer2021-110

gitlab 地址：


<!-- vim-markdown-toc GFM -->

* [配色](#配色)
* [模块说明](#模块说明)
	* [local scan 本地扫描模块](#local-scan-本地扫描模块)
		* [check current id](#check-current-id)
		* [path](#path)
		* [system info](#system-info)
		* [user info](#user-info)
		* [file premission](#file-premission)
		* [软件包版本漏洞检查](#软件包版本漏洞检查)
		* [Function 函数](#function-函数)
		* [MountOption 函数](#mountoption-函数)
		* [selinux检查](#selinux检查)
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

## 模块说明

### local scan 本地扫描模块

#### check current id

检查当前的UID是否为root, 兼容Solaris, SunOS和Linux(包括Euler)

#### path

检查SetUID, 若不正常，即退出。

检查当前工作目录，`WorkDir`

#### system info

检查系统信息。

检查内核信息并输出，包括内核版本, 编译使用的gcc版本，编译的时间和release信息。

#### user info

检查用户信息。

检查hostname和id, 检查口令是否以hash存储，检查上一次登录的用户。

#### file premission

检查目录下文件的权限。

#### 软件包版本漏洞检查

利用OVAL，根据软件包版本检查是否存在CVE漏洞。

#### Function 函数

调用函数。

#### MountOption 函数

检查fs的挂载选项。

/etc/fstab 的数据项：设备名称(实际设备名称或设备名称标签), 挂载点, 分区的类型(fs)，挂载选项, dump选项(0/1),fsck选项(0/1)

> 为了增加Linux系统安全性，建议将/tmp目录单独的挂载于一个独立的系统分区之上。但是仅仅挂载还不够，需要在挂载时为该分区指定nodev/nosuid/noexec选项，才能提高tmp文件目录的安全性。

`/tmp`挂载安全的选项参考: https://www.huaweicloud.com/articles/22202d2c18e5c9e28e2ee8374bc9b667.html

#### selinux检查

检查是否开启了SELinux

### ER emergency response 应急响应模块

详见代码注释

#### 基本检查

`/tmp`下文件 `init.d`下services, `$PATH`

#### 文件检查

输入文件类型、指定目录，检查该目录下24h改变过的/有777权限的该类型文件

输入时间、指定目录，检查该目录下该时间改变过的文件

#### 进程检查

网络连接命令检查可疑PID

输入PID, 查看详情

检查隐藏的process

#### history和log检查

检查命令记录中的wget ssh scp tar zip, 匹配ssh中IP

检查有root权限/能登录的users, 列出所有用户最后一次登录，列出用户登录情况

#### webshell检查

基于文件的webshell检查, 支持php asp jsp
