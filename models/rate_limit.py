from datetime import timedelta

from odoo import api, fields, models


class OAuthRateLimit(models.Model):
    _name = "auth_oidc.rate_limit"
    _description = "OIDC Rate Limit Bucket"
    _rec_name = "key"

    key = fields.Char(required=True, index=True)
    window_start = fields.Datetime(required=True, index=True)
    count = fields.Integer(default=0)

    _sql_constraints = [
        ("auth_oidc_rate_limit_key_window_unique", "unique(key, window_start)", "Rate limit window already exists."),
    ]

    @api.model
    def register_hit(self, key, limit, window_seconds):
        """Increment bucket and return (allowed, retry_after_seconds)."""
        now = fields.Datetime.now()
        window_open = now - timedelta(seconds=window_seconds)
        bucket = self.search(
            [
                ("key", "=", key),
                ("window_start", ">=", fields.Datetime.to_string(window_open)),
            ],
            limit=1,
        )
        if not bucket:
            self.create({"key": key, "window_start": now, "count": 1})
            return True, 0

        # Reset bucket when outside window
        if fields.Datetime.to_datetime(bucket.window_start) < window_open:
            bucket.write({"window_start": now, "count": 1})
            return True, 0

        if bucket.count >= limit:
            retry_after = window_seconds - (
                now - fields.Datetime.to_datetime(bucket.window_start)
            ).total_seconds()
            return False, max(1, int(retry_after))

        bucket.count += 1
        return True, 0
