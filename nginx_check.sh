#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo " \                 Nginx日志安全分析脚本 V1.0            / "
echo " ========================================================= "
echo " # 支持Nginx日志分析，攻击告警分析等                    "
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo -e "\n"

#此脚本是参考nmgxy/klionsec修改而来,重新添加了一些特征，只用来临时救急，还是推荐到ELK或者Splunk中分析

#功能
###统计Top 20 地址
###SQL注入分析
###SQL注入 FROM查询统计
###扫描器/常用黑客工具
###漏洞利用检测
###敏感路径访问
###文件包含攻击
###HTTP Tunnel
###Webshell
###寻找响应长度的url Top 20
###寻找罕见的脚本文件访问
###寻找302跳转的脚本文件

#如果存在多个access文件或者有多个access.x.gz 建议先zcat access*.gz >> access.log文件中
#设置分析结果存储目录,结尾不能加/
outfile=/tmp/logs
#如果目录以存在则清空，未存在则新建目录
if [ -d $outfile ]; then
    rm -rf $outfile/*
else
    mkdir -p $outfile
fi
#设置nginx日志目录，结尾必须加/
access_dir=/var/log/nginx/
#设置文件名，如果文件名为access那么匹配的是access*文件
access_log=access
#判断日志文件是否存在
num=$(ls ${access_dir}${access_log}* | wc -l) >/dev/null 2>&1
if [ $num -eq 0 ]; then
    echo '日志文件不存在'
    exit 1
fi
echo -e "\n"

# 验证操作系统是debian系还是centos
OS='None'
if [ -e "/etc/os-release" ]; then
    source /etc/os-release
    case ${ID} in
    "debian" | "ubuntu" | "devuan")
        OS='Debian'
        ;;
    "centos" | "rhel fedora" | "rhel")
        OS='Centos'
        ;;
    *) ;;
    esac
fi

if [ $OS = 'None' ]; then
    if command -v apt-get >/dev/null 2>&1; then
        OS='Debian'
    elif command -v yum >/dev/null 2>&1; then
        OS='Centos'
    else
        echo -e "\n不支持这个系统\n"
        echo -e "已退出"
        exit 1
    fi
fi

# 检测ag软件有没有安装
if ag -V >/dev/null 2>&1; then
    echo -e "\e[00;32msilversearcher-ag已安装 \e[00m"
else
    if [ $OS = 'Centos' ]; then
        yum -y install the_silver_searcher >/dev/null 2>&1
    else
        apt-get -y install silversearcher-ag >/dev/null 2>&1
    fi

fi
#如果检测别的日志请手动替换偏移，例如awk的$7代表url，$9代表状态码，$10代表长度,本脚本是以nginx日志为基础

echo "分析结果日志：${outfile}"
echo "Nginx日志目录：${access_dir}"
echo "Nginx文件名：${access_log}"
echo -e "\n"

echo -e "\e[00;31m[+]TOP 20 IP 地址\e[00m"
ag -a -o --nofilename '((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}' ${access_dir}${access_log}* | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/top20.log
echo -e "\n"

echo -e "\e[00;31m[+]SQL注入攻击分析\e[00m"
#在SQL注入中排除掉了一些扫描css/js/png图片类等无用告警，并且重点筛选状态码200或者500的告警
ag -a "xp_cmdshell|%20xor|%20and|%20AND|%20or|%20OR|select%20|%20and%201=1|%20and%201=2|%20from|%27exec|information_schema.tables|load_file|benchmark|substring|table_name|table_schema|%20where%20|%20union%20|%20UNION%20|concat\(|concat_ws\(|%20group%20|0x5f|0x7e|0x7c|0x27|%20limit|\bcurrent_user\b|%20LIMIT|version%28|version\(|database%28|database\(|user%28|user\(|%20extractvalue|%updatexml|rand\(0\)\*2|%20group%20by%20x|%20NULL%2C|sqlmap" ${access_dir}${access_log}* | ag -v '/\w+\.(?:js|css|html|jpg|jpeg|png|htm|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >${outfile}/sql.log
awk '{print "SQL注入攻击" NR"次"}' ${outfile}/sql.log | tail -n1
echo "SQL注入 TOP 20 IP地址"
ag -o '(?<=:)((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}' ${outfile}/sql.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/sql_top20.log
# 重点关注from查询，是否存在脱裤行为，排除扫描行为
echo "SQL注入 FROM 查询"
cat ${outfile}/sql.log | ag '\bfrom\b' | ag -v 'information_schema' >${outfile}/sql_from_query.log
awk '{print "SQL注入FROM查询" NR"次"}' ${outfile}/sql_from_query.log | tail -n1
echo -e "\n"

echo -e "\e[00;31m[+]扫描器scan & 黑客工具\e[00m"
ag -a "acunetix|by_wvs|nikto|netsparker|HP404|nsfocus|WebCruiser|owasp|nmap|nessus|HEAD /|AppScan|burpsuite|w3af|ZAP|openVAS|.+avij|.+angolin|360webscan|webscan|XSS@HERE|XSS%40HERE|NOSEC.JSky|wwwscan|wscan|antSword|WebVulnScan|WebInspect|ltx71|masscan|python-requests|Python-urllib|WinHttpRequest" ${access_dir}${access_log}* | ag -v '/\w+\.(?:js|css|jpg|jpeg|png|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >${outfile}/scan.log
awk '{print "共检测到扫描攻击" NR"次"}' ${outfile}/scan.log | tail -n1
echo "扫描工具流量 TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/scan.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/scan_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]敏感路径访问\e[00m"
ag -a "/_cat/|/_config/|include=|phpinfo|info\.php|/web-console|JMXInvokerServlet|/manager/html|axis2-admin|axis2-web|phpMyAdmin|phpmyadmin|/admin-console|/jmx-console|/console/|\.tar.gz|\.tar|\.tar.xz|\.xz|\.zip|\.rar|\.mdb|\.inc|\.sql|/\.config\b|\.bak|/.svn/|/\.git/|\.hg|\.DS_Store|\.htaccess|nginx\.conf|\.bash_history|/CVS/|\.bak|wwwroot|备份|/Web.config|/web.config|/1.txt|/test.txt" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/dir.log
awk '{print "共检测到针对敏感文件扫描" NR"次"}' ${outfile}/dir.log | tail -n1
echo "敏感文件访问流量 TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/dir.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/dir_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]漏洞利用检测\e[00m"
ag -a "%00|/win.ini|/my.ini|\.\./\.\./|/etc/shadow|%0D%0A|file:/|gopher:/|dict:/|WindowsPowerShell|/wls-wsat/|call_user_func_array|uddiexplorer|@DEFAULT_MEMBER_ACCESS|@java\.lang\.Runtime|OgnlContext|/bin/bash|cmd\.exe|wget\s|curl\s|s=/index/\think" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/exploit.log
awk '{print "漏洞利用探测" NR"次"}' ${outfile}/exploit.log | tail -n1
echo "漏洞利用检测 TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/exploit.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/exploit_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]webshell\e[00m"
ag -a "=whoami|dbname=|exec=|cmd=|\br57\b|\bc99\b|\bc100\b|\bb374k\b|adminer.php|eval\(|assert\(|%eval|%execute|tunnel\.[asp|php|jsp|aspx]{3,4}|makewebtaski|ma\.[asp|php|jsp|aspx]{3,4}|\bup\.[asp|php|jsp|aspx]{3,4}|cmd\.[asp|php|jsp|aspx]{3,4}|201\d\.[asp|php|jsp|aspx]{3,4}|xiaoma\.[asp|php|jsp|aspx]{3,4}|shell\.[asp|php|jsp|aspx]{3,4}|404\.[asp|php|jsp|aspx]{3,4}|tom\.[asp|php|jsp|aspx]{3,4}|k8cmd\.[asp|php|jsp|aspx]{3,4}|ver[0-9]{3,4}\.[asp|php|jsp|aspx]{3,4}|\.aar|[asp|php|jsp|aspx]{3,4}spy\.|o=vLogin|aioshell|admine|ghost\.[asp|php|jsp|aspx]{3,4}|r00ts|90sec|t00ls|editor\.aspx|wso\.[asp|aspx]{3,4}" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/webshell.log
awk '{print "共检测到webshell行为" NR "次"}' ${outfile}/webshell.log | tail -n1
echo "Webshell TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/webshell.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/webshell_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]HTTP Tunnel\e[00m"
#Regeorg代理特征
ag -a "cmd=disconnect|cmd=read|cmd=forward|cmd=connect|127.0.0.1" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' | tee -a ${outfile}/tunnel.log
awk '{print "共检测到隧道行为" NR "次"}' ${outfile}/tunnel.log | tail -n1
echo -e "\n"

echo -e "\e[00;31m[+]Top 20 url响应长度\e[00m"
# 查找url响应长度最长的url排序，目的是有没有下载服务器的一些打包文件
len=$(cat ${access_dir}${access_log}* | awk '{print $10}' | sort -nr | head -n 20)
echo $len | awk 'BEGIN{ RS=" " }{ print $0 }' | xargs -i{} ag -a --nocolor '\d+\s{}\s' ${access_dir}${access_log}* | awk '{print $7,$10}' | sort | uniq | sort -k 2 -nr | tee -a ${outfile}/url_rsp_len.log
echo -e "\n"

echo -e "\e[00;31m[+]罕见的脚本文件访问\e[00m"
echo "访问量特别特别少的脚本文件极有可能是webshell"
cat ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a ${outfile}/rare_url.log
echo -e "\n"

echo -e "\e[00;31m[+]302跳转\e[00m"
echo "此目的是寻找一些登录成功的脚本文件"
cat ${access_dir}${access_log}* | awk '($9==302)||($9==301) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a ${outfile}/302_goto.log
echo -e "\n"
