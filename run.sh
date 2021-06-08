#!/usr/bin/env bash

clear

_run_file='/tmp/test.json'

#--Color Code
Cls="\033[0m"
Red="\033[1;31m"
Green="\033[1;32m"
Yellow="\033[1;33m"
Blue="\033[1;34m"
Purple="\033[1;35m"

#--入站,及其DNS;
__Inbounds_localhost() {
    cat << EOF #> ${_run_file}
{
        "log": {
        "loglevel": "warning"
    },
        "inbounds": [
        {
            "listen": "${_in_ip}",
            "port": ${_input_http},
            "protocol": "http",
            "settings": {
                "allowTransparent": true,
                "timeout": 300
            },
            "sniffing": {
        },
            "tag": "Http_IN"
        },
        {
            "listen": "${_in_ip}",
            "port": ${_input_socks},
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "ip": "127.0.0.1",
                "udp": true
            },
            "sniffing": {
        },
            "tag": "Socks_IN"
        }
    ],
EOF
}

#--Mux和DNS;
__Mux_dns() {
    cat << EOF #>> ${_run_file}
    "mux": {
        "enabled": ${_mux},
        "concurrency": 8
    },
        "dns": {
        "servers": [
            {
                "address": "8.8.8.8",
                "address": "1.1.1.1",
                "address": "8.8.4.4",
                "domains": [
                    "geosite:geolocation-!cn"
                ]
            },
            {
                "address": "223.6.6.6",
                "domains": [
                    "geosite:cn"
                ],
                "expectIPs": [
                    "geoip:cn"
                ]
            },
            {
                "address": "223.5.5.5",
                "address": "119.29.29.29",
                "address": "114.114.114.114",
                "address": "114.114.115.115",
                "address": "180.76.76.76",
                "address": "1.2.4.8",
                "address": "182.254.118.118",
                "address": "210.2.4.8",
                "domains": [
                    "geosite:cn"
                ]
            },
            "localhost"
        ]
    },
EOF
}

#--超级牛力Vless+tcp+xtls出站;
__Vless_tcp_xtls() {
    cat << EOF #>> ${_run_file}
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "${_input_addr}",
                        "port": 443,
                        "users": [
                            {
                                "id": "${_input_uuid}",
                                "flow":  "xtls-rprx-splice",
                                "encryption": "none",
                                "level": 0
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "serverName": "${_input_addr}",
                    "allowInsecure": false
                }
        },
            "tag": "PROXY"
        },
        {
            "protocol": "freedom",
            "sendThrough": "0.0.0.0",
            "settings": {
                "domainStrategy": "AsIs",
                "redirect": ":0"
            },
            "streamSettings": {
        },
            "tag": "DIRECT"
        },
        {
            "protocol": "blackhole",
            "sendThrough": "0.0.0.0",
            "settings": {
                "response": {
                    "type": "none"
                }
        },
            "streamSettings": {
        },
            "tag": "BLACKHOLE"
        }
    ],
EOF
}

#--Vless+Websocket+Tls出站;
__Vless_ws_tls() {
    cat << EOF #>> ${_run_file}
     "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "${_input_addr}",
                        "port": 443,
                        "users": [
                            {
                                "id": "${_input_uuid}",
                                "encryption": "none",
                                "level": 0
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "${_input_addr}"
                },
                "wsSettings": {
                    "path": "/websocket"
                }
        },
            "tag": "PROXY"
        },
        {
            "protocol": "freedom",
            "sendThrough": "0.0.0.0",
            "settings": {
                "domainStrategy": "AsIs",
                "redirect": ":0"
            },
            "streamSettings": {
        },
            "tag": "DIRECT"
        },
        {
            "protocol": "blackhole",
            "sendThrough": "0.0.0.0",
            "settings": {
                "response": {
                    "type": "none"
                }
        },
            "streamSettings": {
        },
            "tag": "BLACKHOLE"
        }
    ],
EOF
}

#--Vless+Tcp+Tls出站;
__Vless_tcp_tls() {
    cat << EOF #>> ${_run_file}
      "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "${_input_addr}",
                        "port": 443,
                        "users": [
                            {
                                "id": "${_input_uuid}",
                                "encryption": "none",
                                "level": 0
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "${_input_addr}"
                }
        },
            "tag": "PROXY"
        },
        {
            "protocol": "freedom",
            "sendThrough": "0.0.0.0",
            "settings": {
                "domainStrategy": "AsIs",
                "redirect": ":0"
            },
            "streamSettings": {
        },
            "tag": "DIRECT"
        },
        {
            "protocol": "blackhole",
            "sendThrough": "0.0.0.0",
            "settings": {
                "response": {
                    "type": "none"
                }
        },
            "streamSettings": {
        },
            "tag": "BLACKHOLE"
        }
    ],
EOF
}

#--Trojan+Tcp+Tls出站;
__Trojan_tcp_tls() {
    cat << EOF #>> ${_run_file}
      "outbounds": [
        {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": "${_input_addr}",
                        "port": 443,
                        "password": "${_input_uuid}",
                        "level": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "${_input_addr}"
                }
        },
            "tag": "PROXY"
        },
        {
            "protocol": "freedom",
            "sendThrough": "0.0.0.0",
            "settings": {
                "domainStrategy": "AsIs",
                "redirect": ":0"
            },
            "streamSettings": {
        },
            "tag": "DIRECT"
        },
        {
            "protocol": "blackhole",
            "sendThrough": "0.0.0.0",
            "settings": {
                "response": {
                    "type": "none"
                }
        },
            "streamSettings": {
        },
            "tag": "BLACKHOLE"
        }
    ],
EOF
}

#--Vmess+Websocket+Tls,出站;
__Vmess_ws_tls() {
    cat << EOF #>> ${_run_file}
     "outbounds": [
        {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "${_input_addr}",
                        "port": 443,
                        "users": [
                            {
                                "id": "${_input_uuid}",
                                "security": "none",
                                "level": 0
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "${_input_addr}"
                },
                "wsSettings": {
                    "path": "/vmessws"
                }
        },
                        "tag": "PROXY"
                    },
        {
            "protocol": "freedom",
            "sendThrough": "0.0.0.0",
            "settings": {
                "domainStrategy": "AsIs",
                "redirect": ":0"
            },
            "streamSettings": {
        },
            "tag": "DIRECT"
        },
        {
            "protocol": "blackhole",
            "sendThrough": "0.0.0.0",
            "settings": {
                "response": {
                    "type": "none"
                }
        },
            "streamSettings": {
        },
            "tag": "BLACKHOLE"
        }
    ],
EOF
}

#--Vmess+Tcp+Tls,出站;
__Vmess_tcp_tls() {
    cat << EOF #>> ${_run_file}
        "outbounds": [
        {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "${_input_addr}",
                        "port": 443,
                        "users": [
                            {
                                "id": "${_input_uuid}",
                                "security": "none",
                                "level": 0
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "${_input_addr}"
                },
                "tcpSettings": {
                    "header": {
                        "type": "http",
                        "request": {
                            "path": [
                                "/vmesstcp"
                            ]
                        }
                }
        }
},
            "tag": "PROXY"
        },
        {
            "protocol": "freedom",
            "sendThrough": "0.0.0.0",
            "settings": {
                "domainStrategy": "AsIs",
                "redirect": ":0"
            },
            "streamSettings": {
        },
            "tag": "DIRECT"
        },
        {
            "protocol": "blackhole",
            "sendThrough": "0.0.0.0",
            "settings": {
                "response": {
                    "type": "none"
                }
        },
            "streamSettings": {
        },
            "tag": "BLACKHOLE"
        }
    ],
EOF
}

#--丢弃色情网站及其IP,广告域名,大陆域名,大陆IP,局域网IP直连;
__Route_0() {
    cat << EOF #>> ${_run_file}
     "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all"
                ],
                "outboundTag": "BLACKHOLE"
            },
            {
                "type": "field",
                "domain": [
                    "pornhub.com",
                    "xxx.com",
                    "ponurl.com",
                    "redtube.com",
                    "xnxx.com",
                    "qingse.one",
                    "9aabs.club",
                    "uux68.com",
                    "javhd.com",
                    "22dy.me",
                    "theporndude.com",
                    "141jj.com",
                    "porndude.p67z.com",
                    "91porn.com",
                    "theporndude.com",
                    "9ast.club",
                    "mangotporn.com",
                    "seju8.com",
                    "thepornmap.com",
                    "mrporngeek.com",
                    "fanqianglu.com",
                    "whichav.video",
                    "pornsitesnow.com",
                    "pornsites.xxx",
                    "hotporn.today",
                    "seju.app",
                    "kokqq.com",
                    "thepornbest.com",
                    "xhamster.com",
                    "redhdtube.xxx",
                    "redtube.zone",
                    "redtubepornhd.com",
                    "xbx.mobi",
                    "thisav.com",
                    "fuqvids.com",
                    "relax-porn.com",
                    "hostiex.com",
                    "fullporn.online",
                    "red-tube.video"
                ],
                "outboundTag": "BLACKHOLE"
            },
            {
                "type": "field",
                "ip": [
                    "103.39.76.66",
                    "108.160.165.8",
                    "66.254.114.41",
                    "157.240.7.5",
                    "172.67.214.183",
                    "104.21.23.247",
                    "45.114.11.238",
                    "162.125.2.6",
                    "69.171.229.73",
                    "67.228.102.32",
                    "108.160.170.45"
                ],
                "outboundTag": "BLACKHOLE"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:geolocation-!cn"
                ],
                "outboundTag": "PROXY"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:cn",
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            },
            {
                "type": "field",
                "ip": [
                    "geoip:cn",
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            }
        ]
    }
}
EOF
}

#--大陆ip,域名直连,局域网ip直连,国外域名走代理,只过滤广告域名;
__Route_1() {
    cat << EOF #>> ${_run_file}
        "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all"
                ],
                "outboundTag": "BLACKHOLE"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:geolocation-!cn"
                ],
                "outboundTag": "PROXY"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:cn",
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            },
            {
                "type": "field",
                "ip": [
                    "geoip:cn",
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            }
        ]
    }
}
EOF
}

#--大陆ip,域名直连,局域网ip直连,国外域名走代理;
__Route_2() {
    cat << EOF #>> ${_run_file}
        "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            },
            {
                "type": "field",
                "ip": [
                    "geoip:cn"
                ],
                "outboundTag": "DIRECT"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:cn"
                ],
                "outboundTag": "DIRECT"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:cn",
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:geolocation-!cn"
                ],
                "outboundTag": "PROXY"
            }
        ]
    }
}
EOF
}

#--局域网ip,直连,其余全部走代理;
__Route_3() {
    cat << EOF #>> ${_run_file}
     "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "DIRECT"
            }
        ]
    }
}
EOF
}

#--局域网连接配置;
__Connection() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}本地共享代理配置;${Cls}\n"
    printf "${Red}(inbounds模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Blue}是否允许来自局域网的连接[Yy/Nn]${Cls}\n"
    read -r -p "请输入:" _input
    case ${_input} in
        [yY])
            _in_ip='0.0.0.0'
            readonly _in_ip
            ;;
        [Nn])
            _in_ip='127.0.0.1'
            readonly _in_ip
            ;;
        *)
            printf "${Red}错误的输入;${Cls}\n"
            __Connection
            ;;
    esac
}

#--socks入站配置;
__Socks_in() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}本地socks入站代理配置;${Cls}\n"
    printf "${Red}(inbounds模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Blue}请输入本地socks端口:${Cls}"
    read -r -p '请输入:' _input_socks
    case $(netstat -ntl |grep -w "${_input_socks}" >/dev/null 2>&1;echo $?) in
        '0')
            printf "${Red}Error,${Purple}端口已占用,请重新输入;${Cls}\n"
            __Socks_in
            ;;
        '1')
            if $(echo ${_input_socks} |grep '[Aa-Zz]' >/dev/null 2>&1); then
                printf "${Red}端口只能是${Green}数字,${Purple}不能是其他字符等;${Cls}\n"
                __Socks_in
            elif (( ${_input_socks}>65535 )); then
                printf "${Red}端口不能大于${Purple}65535;${Cls}\n"
                __Socks_in
            elif (( ${_input_socks}<=1024 )); then
                printf "${Red}端口不能小于或等于${Purple}1024;${Cls}\n"
                __Socks_in
            else
                readonly _input_socks
                __Http_in       #本地http入站配置;
            fi
            ;;
        *)
            printf "${Red}端口只能是${Green}数字,${Purple}不能是其他字符等;${Cls}\n"
            __Socks_in
            ;;
    esac
}

#--http入站配置;
__Http_in() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}本地http入站代理配置;${Cls}\n"
    printf "${Red}(inbounds模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Blue}请输入本地http端口:${Cls}"
    read -r -p '请输入:' _input_http
    case $(netstat -ntl |grep -w "${_input_http}" >/dev/null 2>&1;echo $?) in
        '0')
            printf "${Red}Error,${Purple}端口已占用,请重新输入;${Cls}\n"
            __Http_in
            ;;
        '1')
            if $(echo ${_input_http} |grep '[Aa-Zz]' >/dev/null 2>&1); then
                printf "${Red}端口只能是${Green}数字,${Purple}不能是其他字符等;${Cls}\n"
                __Http_in
            elif (( ${_input_http}==${_input_socks} )); then
                printf "${Red}本地http代理端口和socks端口${Purple}不可重复;${Cls}\n"
                __Http_in
            elif (( ${_input_http}<=1024 )); then
                printf "${Red}端口不能小于或等于${Purple}1024;${Cls}\n"
                __Http_in
            elif (( ${_input_http}>65535 )); then
                printf "${Red}端口不能大于${Purple}65535;${Cls}\n"
                __Http_in
            else
                readonly _input_http
                #__Inbounds_localhost    #配置本地入站;
                __Menu_0                #MUX & DNS配置;
            fi
            ;;
        *)
            printf "${Red}端口只能是${Green}数字,${Purple}不能是其他字符等;${Cls}\n"
            __Http_in
            ;;
    esac
}

#--Mux,DNS配置;
__Menu_0() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Green}为了防止DNS泄漏,默认已经配置为最安全的模式;${Cls}\n"
    printf "${Red}\t\t警告!!请勿随意更改DNS配置;${Cls}\n"
    printf "${Red}(mux模块);和(dns模块);${Cls}\n"
    printf "${Blue}你只需要配置是否启用MUX;${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Green}<--0-->${Red} 退出程序;${Cls}\n"
    printf "${Green}<--1-->${Blue} 模式1-->${Purple} 启用MUX;${Cls}\n"
    printf "${Green}<--2-->${Blue} 模式2-->${Purple} 不启用MUX;${Cls}\n"
    printf "${Green}<--3-->${Blue} 模式3-->${Purple} 返回上级菜单;${Cls}\n"
    read -p '请输入:' _input
    case ${_input} in
        '0')
            exit 0
            ;;
        '1')
            _mux='true'
            readonly _mux
            #__Mux_dns           #配置mux dns;
            __Service_addr
            ;;
        '2')
            _mux='false'
            readonly _mux       #配置mux dns;
            #__Mux_dns
            __Service_addr
            ;;
        '3') 
            Menu_0 
            ;;
        *)  Menu_0 
            ;;
    esac
}

#--服务器地址配置;
__Service_addr() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}服务器地址配置;${Cls}\n"
    printf "${Blue}(outbounds模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Green}请务必确保域名已经成功解析到IP;\n${Cls}"
    read -r -p '请输入:' _input_addr
    if $(ping -c 3 ${_input_addr} >/dev/null 2>&1); then
        printf "${Green}域名已经成功解析到ip;${Cls}\n"
        __Uuid_conf
    elif [ ! ${_input_addr} ]; then
        printf "${Red}Error!,请检查域名是否解析到IP;\n${Cls}\n"
        __Service_addr
    else
        printf "${Red}Error!,请检查域名是否解析到IP;\n${Cls}\n"
        __Service_addr
    fi
}

#--UUID配置;
__Uuid_conf() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}UUID(配置);${Cls}\n"
    printf "${Red}(outbounds模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Red}UUID必须和服务器端一致;${Cls}\n\n"
    printf "${Green}请务必正确输入UUID${Cls}\n"
    read -r -p '请输入:' _input_uuid
    if [ ! ${_input_uuid} ]; then
        printf "${Red}严重错误!!!,UUID格式不正确${Cls}\n"
        __Uuid_conf
    elif $(echo ${_input_uuid} |grep -Eo '[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}' >/dev/null 2>&1); then
        __Menu_1
    else
        #printf "${Red}严重错误!!!,UUID格式不正确${Cls}\n"
        __Uuid_conf
    fi
}

#--出战协议配置;
__Menu_1() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}出站协议配置;${Cls}\n"
    printf "${Red}(outbounds模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Green}<--0-->${Red} 退出程序;${Cls}\n"
    printf "${Green}<--1-->${Blue} 模式1-->${Purple} VLESS+TCP+XTLS${Cls}\n"
    printf "${Green}<--2-->${Blue} 模式2-->${Purple} VLESS+WS+TLS${Cls}\n"
    printf "${Green}<--3-->${Blue} 模式3-->${Purple} VLESS+TCP+TLS${Cls}\n"
    printf "${Green}<--4-->${Blue} 模式4-->${Purple} VMESS+WS+TLS${Cls}\n"
    printf "${Green}<--5-->${Blue} 模式5-->${Purple} VMESS+TCP+TLS${Cls}\n"
    printf "${Green}<--6-->${Blue} 模式6-->${Purple} TROJAN+TCP+TLS${Cls}\n"
    read -r -p '请输入:'  _input
    case ${_input} in
        '0')
            exit 0
            ;;
        '1')
           _Output='__Vless_tcp_xtls'
           readonly _Output
            __Menu_2
            ;;
        '2')
            _Output='__Vless_ws_tls'
           readonly _Output
            __Menu_2
            ;;
        '3')
            _Output='__Vless_tcp_tls'
           readonly _Output
            __Menu_2
            ;;
        '4')
            _Output='__Vmess_ws_tls'
           readonly _Output
            __Menu_2
            ;;
        '5')
            _Output='__Vmess_tcp_tls'
           readonly _Output
            __Menu_2
            ;;
        '6')
            _Output='__Trojan_tcp_tls'
           readonly _Output
            __Menu_2
            ;;
        *)
            clear 
            printf "${Red}错误的输入:${Cls}\n"
            __Menu_1
            ;;
    esac
}

#--路由配置;
__Menu_2() {
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Red}代理规则选择(路由配置);${Cls}\n"
    printf "${Red}(routing模块);${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
    printf "${Green}<--0-->${Red} 退出程序;${Cls}\n"
    printf "${Green}<--1-->${Blue} 模式1-->${Purple} 丢弃色情网站及其IP,广告域名,大陆域名,大陆IP,局域网IP直连;${Cls}\n"
    printf "${Green}<--2-->${Blue} 模式2-->${Purple} 大陆ip,域名直连,局域网ip直连,国外域名走代理,只过滤广告域名;${Cls}\n"
    printf "${Green}<--3-->${Blue} 模式3-->${Purple} 大陆ip,域名直连,局域网ip直连,国外域名走代理;${Cls}\n"
    printf "${Green}<--4-->${Blue} 模式4-->${Purple} 全局代理,所有流量走代理,仅仅绕过局域网IP;${Cls}\n"
    printf "${Green}<--6-->${Red} 返回上一层菜单;${Cls}\n"
    read  -r -p '请输入:'  _input
    case ${_input} in
        '0')
            exit 0
            ;;
        '1')
            _Routing='__Route_0'
            __Config_all     #配置文件生成;
            clear
            printf "${Green}"
            xray -config ${_run_file}
            printf "${Cls}"
            exit 0
            ;;
        '2')
           _Routing=' __Route_1'
            __Config_all     #配置文件生成;
            clear
            printf "${$Blue}"
            xray -config ${_run_file}
            printf "${Cls}"
            exit 0
            ;;
        '3')
            _Routing='__Route_2'
            __Config_all     #配置文件生成;
            clear
            printf "${Purple}"
            xray -config ${_run_file}
            printf "${Cls}"
            exit 0
            ;;
        '4')
            _Routing='__Route_3'
            __Config_all     #配置文件生成;
            clear
            printf "${Red}"
            xray -config ${_run_file}
            printf "${Cls}"
            exit 0
            ;;
        *)
            clear ; __Menu_2
            ;;
    esac
}

#--配置文件生成;
__Config_all() {
    __Inbounds_localhost > ${_run_file}     #配置本地入站;
    __Mux_dns >> ${_run_file}               #配置mux dns;
    ${_Output} >> ${_run_file}                 #出站配置;
    ${_Routing} >> ${_run_file}                #路由配置;
}

main() {
    if [ -f ${_run_file} ]; then
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n"
    printf "${Green}此工具拥有超级之牛力;${Cls}\n"
    printf "${Yellow}++++++++++++++++++++++++++++++++++++${Cls}\n\n"
        printf "${Green}检测到您已经有一份配置文件,是否直接使用它${Cls}\n"
        read -r -p '请输入[Yy/Nn]]:' _input
        case ${_input} in
            [Yy])
                xray -config ${_run_file}
                ;;
            [Nn])
                > ${_run_file}
                __Connection    #共享代理配置;
                __Socks_in      #本地socks代理配置;
                __Menu_0        #MUX DNS配置;
                ;;
            *)
                main
                ;;
        esac
    else
        __Connection    #共享代理配置;
        __Socks_in      #本地socks代理配置;
        __Menu_0        #MUX DNS配置;
    fi
}

main
