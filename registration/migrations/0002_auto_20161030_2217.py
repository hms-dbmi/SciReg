# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2016-10-30 22:17
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='registration',
            old_name='technical_consulatation_interest',
            new_name='technical_consult_interest',
        ),
    ]
