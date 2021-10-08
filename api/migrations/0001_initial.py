# Generated by Django 3.2.6 on 2021-10-07 07:02

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Garages',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('location', models.DecimalField(decimal_places=6, max_digits=9)),
                ('garage_detail', models.TextField(blank=True)),
                ('additional_services', models.TextField(blank=True)),
                ('phone', models.IntegerField(blank=True)),
                ('timing', models.CharField(max_length=500)),
                ('image', models.ImageField(blank=True, null=True, upload_to='images/')),
            ],
        ),
    ]