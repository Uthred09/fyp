from django.urls import path
from .views import (
    dashboard_view,
    discovered_list,
    confirm_discovered_device,
    scan_network_view,
    delete_discovered_device,
    delete_device_view,
)
    
urlpatterns = [
    path('', dashboard_view, name='dashboard'),
    path('discovered/', discovered_list, name='discovered_list'),
    path('discovered/confirm/<int:pk>/', confirm_discovered_device, name='confirm_discovered_device'),
    # New route for scanning:
    path('scan/', scan_network_view, name='scan_network'),
    path('discovered/delete/<int:pk>/', delete_discovered_device, name='delete_discovered_device'),
    path('device/<int:pk>/delete/', delete_device_view, name='delete_device'),
]
