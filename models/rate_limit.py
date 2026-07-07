from datetime import timedelta

from psycopg2 import IntegrityError

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

        # Reuse a single bucket per key. Searching by key alone (not by window)
        # means an aged-out bucket is reset in place instead of orphaning a row and
        # inserting a fresh (key, window_start) pair. That avoids both the
        # unique(key, window_start) violation that surfaced as "Bad Request: Rate
        # limit window already exists." (e.g. an authorize page left open for a long
        # time, then submitted alongside a concurrent request) and unbounded row growth.
        bucket = self.search([("key", "=", key)], order="window_start desc", limit=1)

        if not bucket:
            try:
                with self.env.cr.savepoint():
                    bucket = self.create({"key": key, "window_start": now, "count": 1})
                    # Force the INSERT to run inside the savepoint so a unique-constraint
                    # violation is raised (and caught) HERE, not later at request flush
                    # where Odoo would turn it into a user-facing error page.
                    self.env.flush_all()
                return True, 0
            except IntegrityError:
                # A concurrent request created the bucket first; re-read and count
                # this hit against it.
                bucket = self.search([("key", "=", key)], order="window_start desc", limit=1)
                if not bucket:
                    return True, 0

        # Window elapsed -> reset in place (atomic, same row: no unique collision).
        if fields.Datetime.to_datetime(bucket.window_start) < window_open:
            self.env.cr.execute(
                "UPDATE auth_oidc_rate_limit SET window_start = %s, count = 1 WHERE id = %s",
                [fields.Datetime.to_string(now), bucket.id],
            )
            bucket.invalidate_recordset(["window_start", "count"])
            return True, 0

        # Within the window -> increment atomically in SQL so concurrent requests
        # cannot both read the same count and race past the limit.
        self.env.cr.execute(
            "UPDATE auth_oidc_rate_limit SET count = count + 1 WHERE id = %s RETURNING count",
            [bucket.id],
        )
        new_count = self.env.cr.fetchone()[0]
        bucket.invalidate_recordset(["count"])
        if new_count > limit:
            retry_after = window_seconds - (
                now - fields.Datetime.to_datetime(bucket.window_start)
            ).total_seconds()
            return False, max(1, int(retry_after))
        return True, 0

    @api.autovacuum
    def _gc_rate_limit_buckets(self):
        """Housekeeping: drop buckets whose window ended long ago (any leftover rows
        from older records or transient create races)."""
        cutoff = fields.Datetime.now() - timedelta(days=1)
        self.search([("window_start", "<", fields.Datetime.to_string(cutoff))]).unlink()
