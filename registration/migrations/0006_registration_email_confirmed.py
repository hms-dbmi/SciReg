# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2017-01-13 17:23
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0005_auto_20170104_1640'),
    ]

    operations = [
        migrations.AddField(
            model_name='registration',
            name='email_confirmed',
            field=models.BooleanField(default=False),
        ),
    ]