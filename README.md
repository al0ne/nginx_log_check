# nginx_log_check
Nginx日志安全分析脚本
### 功能

* 统计Top 20 地址
* SQL注入分析
* 扫描器告警分析
* 漏洞利用检测
* 敏感路径访问
* 文件包含攻击
* Webshell
* 寻找响应长度的url Top 20
* 寻找罕见的脚本文件访问
* 寻找302跳转的脚本文件

### Usage
设置报告保存地址 outfile  
设置日志分析目录 access_dir  
设置日志名称 access_log  
./nginx_check.sh

### 参考
nmgxy  
klionsec  
