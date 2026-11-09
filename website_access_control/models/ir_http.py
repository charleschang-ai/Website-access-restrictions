import werkzeug.exceptions

from odoo import models
from odoo.http import request


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _frontend_pre_dispatch(cls):
        super()._frontend_pre_dispatch()
        # also called again while rendering error pages: check each request once
        if not getattr(request, '_wac_checked', False):
            request._wac_checked = True
            cls._wac_check_access()

    @classmethod
    def _wac_check_access(cls):
        Config = request.env['website.access.config'].sudo()
        settings = Config._wac_settings()
        if not settings['enabled'] or Config._wac_is_exempt(request.httprequest.path, settings):
            return
        if request.env.user._is_internal():
            return
        ip, peer_ip = Config._wac_client_ip(settings)
        grant = Config._wac_cookie_grant(settings)
        zh_browser = 'zh' in (request.httprequest.headers.get('Accept-Language') or '').lower()
        decision, rule_id, reason, country = Config._wac_evaluate(ip, grant=grant, zh_browser=zh_browser)
        if not decision:
            return
        Config._wac_log_request(decision, ip, peer_ip, country, rule_id, reason,
                                grant_id=grant[0] if grant else False)
        if decision == 'blocked':
            werkzeug.exceptions.abort(Config._wac_blocked_response(settings))

    @classmethod
    def _post_dispatch(cls, response):
        super()._post_dispatch(response)
        if getattr(request, 'is_frontend', False) and getattr(response, 'mimetype', None) == 'text/html':
            settings = request.env['website.access.config'].sudo()._wac_settings()
            if settings['enabled'] and settings['no_store_pages']:
                response.headers['Cache-Control'] = 'no-store, private'
