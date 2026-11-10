# -*- coding: utf-8 -*-
################################################################################
#    Author: Don Shan
#
################################################################################
{
    'name': 'Website Access Control | Block Countries by IP | Geo IP Blocking | '
            'Region Block | IP Whitelist & Blacklist | Website Access Links',
    'summary': 'Block website visitors by region or IP: Mainland China, Hong Kong, Macao, '
               'Taiwan, allow / block rules by IP, CIDR or country, private access links '
               'for chosen people, CDN real IP support and a full access log.',
    'description': """
Website Access Control
======================
Restrict who can browse the public website:

* block visitors from selected regions (Mainland China, Hong Kong, Macao, Taiwan)
  using a bundled APNIC IP database refreshed monthly
* optionally block Chinese-language browsers, even behind a foreign VPN
* allow / block rules by IP, network (CIDR) or country
* access links that grant a long-lived bypass cookie to designated people,
  revocable one by one
* real visitor IP behind a CDN (Cloudflare, Alibaba Cloud CDN, ...), only read
  from trusted proxies so it cannot be spoofed
* logged-in employees, the login page, the backend, the portal and payment
  callbacks are never blocked
* log-only mode to check decisions before enforcing them, with a full access log
* customizable block page, Simplified Chinese translation included

网站访问控制
============
按地区或 IP 限制谁能访问公开网站:

* 屏蔽中国大陆、香港、澳门、台湾的访客(内置 APNIC IP 库,每月自动更新)
* 可选屏蔽中文浏览器,即使使用海外 VPN
* 按 IP、网段(CIDR)或国家设置放行 / 屏蔽规则
* 访问链接:为指定的人发放长期有效的放行 Cookie,可单独吊销
* 支持 CDN 真实 IP,只信任指定的代理,无法伪造
* 已登录员工、登录页、后台、门户与支付回调始终可访问
* 仅记录模式可先观察再拦截,完整的访问日志
""",
    'version': '19.0.1.0.0',
    'category': 'Website/Website',
    'author': 'Don Shan',
    'maintainer': 'Don Shan',
    'support': '18438630181@163.com',
    'license': 'LGPL-3',
    'depends': ['website'],
    'data': [
        'security/security.xml',
        'security/ir.model.access.csv',
        'data/config_data.xml',
        'views/templates.xml',
        'views/access_grant_views.xml',
        'views/access_config_views.xml',
        'views/access_rule_views.xml',
        'views/access_log_views.xml',
        'views/menus.xml',
    ],
    'images': ['static/description/banner.png'],
    'installable': True,
    'application': False,
    'auto_install': False,
    'price': 30,
    'currency': 'USD',
}
