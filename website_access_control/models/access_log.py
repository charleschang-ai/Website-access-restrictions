from datetime import timedelta

from odoo import api, fields, models


class WebsiteAccessLog(models.Model):
    _name = 'website.access.log'
    _description = 'Website Access Log'
    _order = 'id desc'
    _rec_name = 'ip'

    decision = fields.Selection([
        ('blocked', 'Blocked'),
        ('logged', 'Would Be Blocked'),
        ('allowed_rule', 'Allowed by Rule'),
        ('allowed_link', 'Allowed by Access Link'),
        ('link_granted', 'Access Link Opened'),
    ], required=True, readonly=True, index=True)
    ip = fields.Char(string='Visitor IP', readonly=True, index=True)
    peer_ip = fields.Char(
        string='Connection Address', readonly=True,
        help="Address of the CDN or proxy that forwarded the request, when it differs from the visitor IP.",
    )
    country_code = fields.Char(string='Region', readonly=True, index=True)
    rule_id = fields.Many2one('website.access.rule', string='Rule', readonly=True, ondelete='set null', index=True)
    grant_id = fields.Many2one('website.access.grant', string='Access Link', readonly=True, ondelete='set null', index=True)
    reason = fields.Char(readonly=True)
    url = fields.Char(string='URL', readonly=True)
    user_agent = fields.Char(string='Browser', readonly=True)

    @api.model
    def _cron_purge(self):
        config = self.env['website.access.config'].sudo().search([], limit=1)
        days = config.log_retention_days or 30
        self.sudo().search([('create_date', '<', fields.Datetime.now() - timedelta(days=days))]).unlink()
