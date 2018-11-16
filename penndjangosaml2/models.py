from django.db import models


class LongGroupName(models.Model):
    group_name = models.TextField(blank=False, null=False)
    count = models.IntegerField(blank=False, null=False, default=0)
    create_date = models.DateTimeField(auto_now=True)
    last_update = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} count: {} last updated: {})".format(self.group_name, self.count, self.last_update)
