from werkzeug.exceptions import NotFound

from odoo import http
from odoo.http import request

from ..models.access_config import COOKIE_NAME


class WebsiteAccessController(http.Controller):

    @http.route('/access/<string:token>', type='http', auth='public', methods=['GET'], sitemap=False)
    def access_link(self, token, **kwargs):
        Config = request.env['website.access.config'].sudo()
        settings = Config._wac_settings()
        grant = settings['grants'].get(token)
        if not grant:
            raise NotFound()
        ip, peer_ip = Config._wac_client_ip(settings)
        Config._wac_log_request('link_granted', ip, peer_ip, Config._wac_country(ip), grant_id=grant[0])
        response = request.redirect('/')
        response.set_cookie(
            COOKIE_NAME, token,
            max_age=settings['cookie_days'] * 86400,
            httponly=True, samesite='Lax', secure=request.httprequest.scheme == 'https',
        )
        return response
