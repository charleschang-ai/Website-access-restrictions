{
    'name': 'Website Access Control',
    'summary': 'Block website visitors by region or IP, with allow rules and access links',
    'description': """
Restrict who can browse the public website:

* block visitors from selected regions (Mainland China, Hong Kong, Macao, Taiwan)
  using a bundled APNIC IP database refreshed monthly
* allow / block rules by IP, network (CIDR) or country
* access links that grant a long-lived bypass cookie to designated people
* logged-in employees, the login page, the backend and the portal are never blocked
* log-only mode to check decisions before enforcing them
""",
    'version': '19.0.1.0.0',
    'category': 'Website/Website',
    'author': 'Asta',
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
    'installable': True,
}
