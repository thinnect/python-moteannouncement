from datetime import datetime


class TimestampMixin(object):
    def deserialize(self, *args, **kwargs):
        self.arrived = datetime.utcnow().replace(tzinfo=None)
        super(TimestampMixin, self).deserialize(*args, **kwargs)
