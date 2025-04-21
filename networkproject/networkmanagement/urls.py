from django.urls import path
from . import views  # Import views from the app

urlpatterns = [
    path('', views.network_management_home, name="network_home"), 
    path("change-hostname/", views.change_hostname, name="change_hostname"),
    path('ping/', views.ping_device, name='ping_device'),
    path('set-motd/', views.set_banner_motd, name='set_banner_motd'),
    path('set-vty/', views.set_vty_password, name='set_vty_password'),
    path('set-console/', views.set_console_password, name='set_console_password'),
    path('create-vlan/', views.create_vlan, name='create_vlan'),
]