from . import views
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('user_login/', views.user_login, name='User Login'),
    path('auth_otp/', views.auth_otp, name='Auth OTP'),
    path('add_garage/', views.add_garage, name='add_garage'),
    path('edit_garage/', views.edit_garage, name='edit_garage'),
    path('show_garage/', views.show_garage, name='show_garage'),
    ]