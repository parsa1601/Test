from django.db import models

# Create your models here.


class Notif(models.Model):
    message = models.TextField(max_length=100)
    number = models.IntegerField()



    def ___str___(self):
        self.message


