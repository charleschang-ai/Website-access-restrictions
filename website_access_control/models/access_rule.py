import ipaddress

from odoo import api, fields, models, tools
from odoo.exceptions import ValidationError


class WebsiteAccessRule(models.Model):
    _name = 'website.access.rule'
    _description = 'Website Access Rule'
    _order = 'sequence, id'

    sequence = fields.Integer(default=10)
    # deliberately not named 'active': disabled rules must stay visible in the list
    enabled = fields.Boolean(string='Enabled', default=True)
    rule_type = fields.Selection(
        [('allow', 'Allow'), ('block', 'Block')],
        string='Type', required=True, default='allow',
        help="Allow rules always win over block rules and blocked regions.",
    )
    match_type = fields.Selection(
        [('ip', 'IP / Network'), ('country', 'Country / Region')],
        string='Match', required=True, default='ip',
    )
    value = fields.Char(
        required=True,
        help="An IP address (1.2.3.4), a network in CIDR notation (1.2.3.0/24, 240e::/20) "
             "or a two-letter country code (CN, HK, US...).",
    )
    name = fields.Char(string='Note', help="Who or what this rule is for, e.g. 'Jinan office'.")
    hit_count = fields.Integer(string='Hits', compute='_compute_hits')
    last_hit = fields.Datetime(string='Last Hit', compute='_compute_hits')

    @api.depends('name', 'value')
    def _compute_display_name(self):
        for rule in self:
            rule.display_name = rule.name or rule.value

    def _compute_hits(self):
        stats = {
            rule.id: (count, last)
            for rule, count, last in self.env['website.access.log'].sudo()._read_group(
                [('rule_id', 'in', self.ids)], ['rule_id'], ['__count', 'create_date:max'])
        }
        for rule in self:
            rule.hit_count, rule.last_hit = stats.get(rule.id, (0, False))

    @api.model
    def _normalize_value(self, match_type, value):
        value = (value or '').strip()
        if match_type == 'ip':
            try:
                return str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                raise ValidationError(self.env._("'%s' is not a valid IP address or network.", value)) from None
        if len(value) != 2 or not value.isalpha():
            raise ValidationError(self.env._("'%s' is not a two-letter country code.", value))
        return value.upper()

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            vals['value'] = self._normalize_value(vals.get('match_type', 'ip'), vals.get('value'))
        rules = super().create(vals_list)
        self.env.registry.clear_cache()
        return rules

    def write(self, vals):
        if 'value' in vals or 'match_type' in vals:
            for rule in self:
                super(WebsiteAccessRule, rule).write({
                    'value': self._normalize_value(vals.get('match_type', rule.match_type), vals.get('value', rule.value)),
                })
            vals = {k: v for k, v in vals.items() if k != 'value'}
        res = super().write(vals)
        self.env.registry.clear_cache()
        return res

    def unlink(self):
        res = super().unlink()
        self.env.registry.clear_cache()
        return res

    @api.model
    @tools.ormcache()
    def _wac_rules(self):
        rules = []
        for rule in self.sudo().search([('enabled', '=', True)]):
            value = ipaddress.ip_network(rule.value, strict=False) if rule.match_type == 'ip' else rule.value
            rules.append({
                'id': rule.id,
                'type': rule.rule_type,
                'match': rule.match_type,
                'value': value,
                'label': rule.name or rule.value,
            })
        return tuple(rules)

    @api.model
    def _wac_match(self, rule, ip, country):
        if rule['match'] == 'ip':
            return ip is not None and ip.version == rule['value'].version and ip in rule['value']
        return country == rule['value']
