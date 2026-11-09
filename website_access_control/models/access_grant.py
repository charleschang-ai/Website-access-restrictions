import secrets

from odoo import api, fields, models


class WebsiteAccessGrant(models.Model):
    _name = 'website.access.grant'
    _description = 'Website Access Link'
    _order = 'id'

    name = fields.Char(
        string='Granted To', required=True,
        help="Who this access link is for, e.g. 'Mr. Wang (dealer)'.",
    )
    token = fields.Char(required=True, copy=False, default=lambda self: secrets.token_urlsafe(16))
    enabled = fields.Boolean(default=True, help="Turn off to revoke this person's access immediately.")
    access_url = fields.Char(string='Access Link', compute='_compute_access_url')
    use_count = fields.Integer(string='Visits', compute='_compute_usage')
    last_used = fields.Datetime(string='Last Visit', compute='_compute_usage')

    def _compute_access_url(self):
        base_url = self.get_base_url()
        for grant in self:
            grant.access_url = grant.token and f'{base_url}/access/{grant.token}'

    def _compute_usage(self):
        stats = {
            grant.id: (count, last)
            for grant, count, last in self.env['website.access.log'].sudo()._read_group(
                [('grant_id', 'in', self.ids)], ['grant_id'], ['__count', 'create_date:max'])
        }
        for grant in self:
            grant.use_count, grant.last_used = stats.get(grant.id, (0, False))

    @api.model_create_multi
    def create(self, vals_list):
        grants = super().create(vals_list)
        self.env.registry.clear_cache()
        return grants

    def write(self, vals):
        res = super().write(vals)
        self.env.registry.clear_cache()
        return res

    def unlink(self):
        res = super().unlink()
        self.env.registry.clear_cache()
        return res
