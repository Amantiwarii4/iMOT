# Generated by Django 3.2.6 on 2021-10-07 07:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_alter_garages_phone'),
    ]

    operations = [
        migrations.AlterField(
            model_name='garages',
            name='phone',
            field=models.CharField(blank=True, default='xxxx', max_length=30),
        ),
    ]