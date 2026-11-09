import base64
import ipaddress
import logging
import re
import threading
import time

import requests
from markupsafe import Markup

from odoo import api, fields, models, tools
from odoo.exceptions import UserError
from odoo.http import GeoIP, request
from odoo.tools.misc import file_open

from ..tools import APNIC_URL, IpTable, compact_apnic

_logger = logging.getLogger(__name__)

COOKIE_NAME = 'wac_pass'
IP_VERSION_PARAM = 'website_access_control.ip_data_version'
IP_ATTACHMENT_NAME = 'website_access_control_ip_data.txt'
BUNDLED_IP_FILE = 'website_access_control/data/apnic_ip_ranges.txt'
# Paths that must stay reachable whatever the configuration: login and signup,
# backend, portal, assets, access links, payment callbacks, live chat / bus, and
# the frontend translations without which the login page form stays hidden.
DEFAULT_EXEMPT_PATHS = (
    '/web', '/odoo', '/my', '/access', '/payment', '/websocket', '/mail', '/website/translations',
)
REGION_FIELDS = {'CN': 'block_cn', 'HK': 'block_hk', 'MO': 'block_mo', 'TW': 'block_tw'}

_ip_tables = {}  # dbname -> (data version, IpTable)

# A flood of blocked requests must not turn into a flood of log writes: each one
# takes a second database connection, and a full connection pool fails every
# request of the site. Log the same visitor and decision once per interval, and
# never hold more than a few extra connections per process.
LOG_INTERVAL = 60  # seconds
LOG_MAX_WRITERS = 2
LOG_MAX_KEYS = 10000
_log_last = {}  # (dbname, decision, ip, grant id) -> time.monotonic() of the last log line
_log_writers = threading.BoundedSemaphore(LOG_MAX_WRITERS)


class WebsiteAccessConfig(models.Model):
    _name = 'website.access.config'
    _description = 'Website Access Control Settings'

    enabled = fields.Boolean(
        string='Enable Access Control',
        help="When disabled, the website is open to everyone and nothing is logged.",
    )
    mode = fields.Selection(
        [('log', 'Log Only'), ('block', 'Block')],
        string='Mode', default='log', required=True,
        help="Log Only: visitors are never blocked, but the visits that would be blocked are logged. "
             "Use it right after going live to check the decisions, then switch to Block.",
    )
    block_cn = fields.Boolean(string='Mainland China', default=True)
    block_hk = fields.Boolean(string='Hong Kong')
    block_mo = fields.Boolean(string='Macao')
    block_tw = fields.Boolean(string='Taiwan')
    block_zh_browser = fields.Boolean(
        string='Block Chinese-language Browsers',
        help="Also block anonymous visitors whose browser asks for Chinese pages (Accept-Language "
             "contains 'zh'), whatever their IP. Catches competitors behind a foreign VPN, but also "
             "blocks overseas Chinese-speaking visitors: check the logs in Log Only mode before "
             "enabling it for real.",
    )

    cookie_days = fields.Integer(string='Access Link Validity (days)', default=365, required=True)

    real_ip_header = fields.Char(
        string='Real IP Header',
        help="HTTP header carrying the visitor IP when the website is behind a CDN or proxy, "
             "e.g. Ali-CDN-Real-IP for Alibaba Cloud CDN. Prefer a header the CDN overwrites on "
             "every request (Ali-CDN-Real-IP, X-Real-IP, CF-Connecting-IP). When the header holds "
             "several addresses, the rightmost public one is used, because a visitor can forge the "
             "left part of X-Forwarded-For. The header is only read on requests coming from a "
             "Trusted Proxy. Leave empty to use the connection address, as corrected by proxy_mode.",
    )
    trusted_proxies = fields.Text(
        string='Trusted Proxies',
        help="Addresses or networks (CIDR) of the CDN or proxy that connects to Odoo, one per line, "
             "e.g. the back-to-origin ranges of the CDN. The Real IP Header is only read on requests "
             "whose Connection Address is in this list: anyone else reaching the server directly could "
             "put any address in that header. When empty, the header is ignored.",
    )
    current_ip = fields.Char(string='Your IP As Seen', compute='_compute_current_visitor')
    current_country = fields.Char(string='Your Region As Seen', compute='_compute_current_visitor')
    current_peer_ip = fields.Char(string='Connection Address', compute='_compute_current_visitor')

    block_title = fields.Char(string='Block Page Title', default='网站维护中 | Under Maintenance', required=True)
    block_message = fields.Text(
        string='Block Page Message',
        default='网站正在维护，请稍后再访问。\nThe website is under maintenance, please visit later.',
    )
    no_store_pages = fields.Boolean(
        string='Forbid CDN Caching of Pages', default=True,
        help="Send 'Cache-Control: no-store, private' on website pages, so a CDN cannot serve a cached "
             "page to a blocked visitor without asking the server.",
    )
    exempt_paths = fields.Text(
        string='Extra Exempt Paths',
        help="One path per line (e.g. /shop/payment/webhook). Requests to these paths and their "
             "sub-paths are never blocked, in addition to the login page, backend, portal and payment callbacks.",
    )
    log_retention_days = fields.Integer(string='Keep Logs (days)', default=30, required=True)

    ip_data_date = fields.Char(string='IP Data Date', compute='_compute_ip_data')
    ip_cn_count = fields.Char(string='Mainland China Ranges', compute='_compute_ip_data')

    def _compute_display_name(self):
        for config in self:
            config.display_name = self.env._("Access Control Settings")

    def _compute_current_visitor(self):
        ip = peer_ip = country = False
        if request:
            ip, peer_ip = self._wac_client_ip(self._wac_settings())
            country = self._wac_country(ip) or self.env._('Unknown')
        for config in self:
            config.current_ip, config.current_peer_ip, config.current_country = ip, peer_ip, country

    def _compute_ip_data(self):
        table = self._wac_ip_table()
        date = table.date and f'{table.date[:4]}-{table.date[4:6]}-{table.date[6:]}'
        cn = self.env._('%(v4)s IPv4 / %(v6)s IPv6', v4=table.counts['CN', 'ipv4'], v6=table.counts['CN', 'ipv6'])
        for config in self:
            config.ip_data_date, config.ip_cn_count = date, cn

    @api.constrains('cookie_days', 'log_retention_days')
    def _check_days(self):
        for config in self:
            if config.cookie_days < 1 or config.log_retention_days < 1:
                raise UserError(self.env._("The number of days must be at least 1."))

    @api.constrains('trusted_proxies')
    def _check_trusted_proxies(self):
        for config in self:
            self._wac_parse_networks(config.trusted_proxies)

    @api.model
    def _wac_parse_networks(self, text):
        networks = []
        for value in re.split(r'[\s,;]+', text or ''):
            if not value:
                continue
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                raise UserError(self.env._("'%s' is not a valid IP address or network.", value)) from None
        return tuple(networks)

    def write(self, vals):
        res = super().write(vals)
        self.env.registry.clear_cache()
        return res

    # ------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------

    def action_update_ip_data(self):
        table = self._wac_update_ip_data()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'type': 'success',
                'message': self.env._(
                    "IP data updated (%(date)s): %(count)s Mainland China ranges.",
                    date=table.date, count=table.counts['CN', 'ipv4'] + table.counts['CN', 'ipv6'],
                ),
                'next': {'type': 'ir.actions.client', 'tag': 'soft_reload'},
            },
        }

    # ------------------------------------------------------------
    # Cached settings and IP data
    # ------------------------------------------------------------

    @api.model
    @tools.ormcache()
    def _wac_settings(self):
        config = self.sudo().search([], limit=1)
        if not config:
            return {'enabled': False}
        extra = tuple(
            '/' + path.strip().strip('/') for path in (config.exempt_paths or '').splitlines() if path.strip().strip('/')
        )
        return {
            'enabled': config.enabled,
            'mode': config.mode,
            'regions': frozenset(cc for cc, fname in REGION_FIELDS.items() if config[fname]),
            'block_zh': config.block_zh_browser,
            'grants': {
                grant['token']: (grant['id'], grant['name'])
                for grant in self.env['website.access.grant'].sudo().search_read(
                    [('enabled', '=', True)], ['token', 'name'])
            },
            'cookie_days': config.cookie_days,
            'real_ip_header': (config.real_ip_header or '').strip(),
            'trusted_proxies': self._wac_parse_networks(config.trusted_proxies),
            'exempt_paths': DEFAULT_EXEMPT_PATHS + extra,
            'block_title': config.block_title,
            'block_message': config.block_message or '',
            'no_store_pages': config.no_store_pages,
        }

    @api.model
    def _wac_ip_table(self):
        version = self.env['ir.config_parameter'].sudo().get_param(IP_VERSION_PARAM) or 'bundled'
        cached = _ip_tables.get(self.env.cr.dbname)
        if cached and cached[0] == version:
            return cached[1]
        table = None
        if version != 'bundled':
            # the web client reads records with bin_size=True, which would return the size instead of the content
            attachment = self.env['ir.attachment'].sudo().with_context(bin_size=False).search(
                [('res_model', '=', self._name), ('name', '=', IP_ATTACHMENT_NAME)], limit=1)
            try:
                table = IpTable(attachment.raw.decode()) if attachment.raw else None
            except (ValueError, UnicodeDecodeError):
                _logger.exception("Website access control: invalid downloaded IP data, using the bundled data")
                table = None
            if table is not None and not table.counts['CN', 'ipv4']:
                table = None
        if table is None:
            with file_open(BUNDLED_IP_FILE) as f:
                table = IpTable(f.read())
        _ip_tables[self.env.cr.dbname] = (version, table)
        return table

    @api.model
    def _wac_update_ip_data(self):
        try:
            response = requests.get(APNIC_URL, timeout=120)
            response.raise_for_status()
        except requests.RequestException as e:
            raise UserError(self.env._("Could not download the IP data from APNIC: %s", e)) from e
        compact = compact_apnic(response.text)
        table = IpTable(compact)
        if table.counts['CN', 'ipv4'] < 1000:
            raise UserError(self.env._("The downloaded IP data looks incomplete, the current data is kept."))
        Attachment = self.env['ir.attachment'].sudo().with_context(bin_size=False)
        attachment = Attachment.search([('res_model', '=', self._name), ('name', '=', IP_ATTACHMENT_NAME)], limit=1)
        vals = {'datas': base64.b64encode(compact.encode()), 'mimetype': 'text/plain'}
        if attachment:
            attachment.write(vals)
        else:
            Attachment.create({'name': IP_ATTACHMENT_NAME, 'res_model': self._name, **vals})
        self.env['ir.config_parameter'].sudo().set_param(IP_VERSION_PARAM, fields.Datetime.now().isoformat())
        _logger.info("Website access control: IP data updated to %s (%d ranges)", table.date, len(table))
        return table

    @api.model
    def _cron_update_ip_data(self):
        try:
            self._wac_update_ip_data()
        except UserError as e:
            _logger.warning("Website access control: IP data update failed, keeping the current data: %s", e)

    # ------------------------------------------------------------
    # Request evaluation
    # ------------------------------------------------------------

    @api.model
    def _wac_parse_ip(self, value):
        try:
            ip = ipaddress.ip_address((value or '').strip())
        except ValueError:
            return None
        return getattr(ip, 'ipv4_mapped', None) or ip

    @api.model
    def _wac_client_ip(self, settings):
        """Return (visitor IP, connection address) of the current request."""
        peer_ip = request.httprequest.remote_addr
        header = settings.get('real_ip_header')
        if header and self._wac_is_trusted_proxy(peer_ip, settings):
            # Rightmost public address: a visitor can pre-fill entries on the
            # left of an appending header (X-Forwarded-For), the proxies append
            # the address they saw on the right.
            fallback = None
            for value in reversed(request.httprequest.headers.get(header, '').split(',')):
                value = value.strip()
                ip = self._wac_parse_ip(value)
                if ip:
                    fallback = fallback or value
                    if ip.is_global:
                        return value, peer_ip
            if fallback:
                return fallback, peer_ip
        return peer_ip, peer_ip

    @api.model
    def _wac_is_trusted_proxy(self, peer_ip, settings):
        peer = self._wac_parse_ip(peer_ip)
        return peer is not None and any(
            peer.version == network.version and peer in network for network in settings.get('trusted_proxies', ())
        )

    @api.model
    def _wac_country(self, ip):
        ip = self._wac_parse_ip(ip) if isinstance(ip, str) else ip
        if not ip or not ip.is_global:
            return None
        country = self._wac_ip_table().country(ip)
        if not country:
            try:
                country = GeoIP(str(ip)).country.iso_code
            except Exception:  # noqa: BLE001
                country = None
        return country

    @api.model
    def _wac_is_exempt(self, path, settings):
        return any(path == p or path.startswith(p + '/') for p in settings['exempt_paths'])

    @api.model
    def _wac_evaluate(self, ip, grant=None, zh_browser=False):
        """Decide what to do with an anonymous visitor.

        :param grant: (id, name) of the access link found in the visitor's cookie, if any
        :param zh_browser: whether the browser asks for Chinese pages
        :return: (decision, rule id, reason, country) where decision is None when the
            visitor is let through without being logged.
        """
        settings = self._wac_settings()
        ip_obj = self._wac_parse_ip(ip) if isinstance(ip, str) else ip
        country = self._wac_country(ip_obj)
        Rule = self.env['website.access.rule'].sudo()
        rules = Rule._wac_rules()
        block = next((r for r in rules if r['type'] == 'block' and Rule._wac_match(r, ip_obj, country)), None)
        region_hit = country in settings['regions']
        zh_hit = settings['block_zh'] and zh_browser
        if not block and not region_hit and not zh_hit:
            return None, False, '', country
        if block:
            reason = block['label']
        elif region_hit:
            reason = self.env._('Region %s', country)
        else:
            reason = self.env._('Chinese-language browser')
        allow = next((r for r in rules if r['type'] == 'allow' and Rule._wac_match(r, ip_obj, country)), None)
        if allow:
            return 'allowed_rule', allow['id'], allow['label'], country
        if grant:
            return 'allowed_link', False, reason, country
        decision = 'blocked' if settings['mode'] == 'block' else 'logged'
        return decision, block['id'] if block else False, reason, country

    @api.model
    def _wac_cookie_grant(self, settings):
        """Return (id, name) of the enabled access link whose token is in the visitor's cookie."""
        cookie = request.httprequest.cookies.get(COOKIE_NAME)
        return settings['grants'].get(cookie) if cookie else None

    @api.model
    def _wac_log(self, vals):
        """Write a log line in its own transaction: the request itself is aborted or may be read-only."""
        if not _log_writers.acquire(blocking=False):
            _logger.debug("Website access control: too many concurrent log writes, log line dropped")
            return
        try:
            with self.env.registry.cursor() as cr:
                self.env(cr=cr, su=True)['website.access.log'].create(vals)
        except Exception:  # noqa: BLE001
            _logger.warning("Website access control: could not write the access log", exc_info=True)
        finally:
            _log_writers.release()

    @api.model
    def _wac_log_throttled(self, key):
        """Return whether a log line for ``key`` was already written less than LOG_INTERVAL ago."""
        now = time.monotonic()
        if len(_log_last) > LOG_MAX_KEYS:
            for k, last in list(_log_last.items()):
                if now - last >= LOG_INTERVAL:
                    _log_last.pop(k, None)
            if len(_log_last) > LOG_MAX_KEYS:  # many distinct visitors within one interval
                _log_last.clear()
        last = _log_last.get(key)
        if last is not None and now - last < LOG_INTERVAL:
            return True
        _log_last[key] = now
        return False

    @api.model
    def _wac_log_request(self, decision, ip, peer_ip, country, rule_id=False, reason='', grant_id=False):
        if self._wac_log_throttled((self.env.cr.dbname, decision, ip, grant_id)):
            return
        httprequest = request.httprequest
        self._wac_log({
            'decision': decision,
            'ip': ip,
            'peer_ip': peer_ip if peer_ip != ip else False,
            'country_code': country or False,
            'rule_id': rule_id,
            'grant_id': grant_id,
            'reason': reason,
            'url': httprequest.full_path.rstrip('?')[:1000],
            'user_agent': (httprequest.user_agent.string or '')[:500],
        })

    @api.model
    def _wac_blocked_response(self, settings):
        html = self.env['ir.qweb']._render('website_access_control.blocked_page', {
            'title': settings['block_title'],
            'message': settings['block_message'],
        })
        return request.make_response(Markup('<!DOCTYPE html>\n') + html, status=503, headers=[
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Cache-Control', 'no-store, private, max-age=0'),
            ('Retry-After', '3600'),
        ])
