from django.contrib import admin
from .models import Device, NetworkInterface, DiscoveredDevice

admin.site.register(Device)
admin.site.register(NetworkInterface)
admin.site.register(DiscoveredDevice)