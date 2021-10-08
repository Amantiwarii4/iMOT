from . import views
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('user_login/', views.user_login, name='User Login'),
    path('auth_otp/', views.auth_otp, name='Auth OTP'),
    path('add_garage/', views.add_garage, name='add_garage'),
    path('edit_garage/', views.edit_garage, name='edit_garage'),
    path('show_garage/', views.show_garage, name='show_garage'),
    path('admin_login/', views.admin_login, name='admin_login'),
    path('auth_otp/', views.auth_otp, name='auth_otp'),
    path('user_login/', views.user_login, name='user_login'),
    path('add_user/', views.add_user, name='add_user'),
    path('user_list/', views.user_list, name='user_list'),
]
