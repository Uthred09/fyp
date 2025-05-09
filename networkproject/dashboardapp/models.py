from django.db import models
from django.utils.timezone import now

class DiscoveredDevice(models.Model):
    """
    Stores devices automatically found by scanning a subnet but not yet confirmed.
    """
    ip_address = models.GenericIPAddressField(protocol='IPv4', unique=True)
    hostname = models.CharField(max_length=100, blank=True)
    vendor = models.CharField(max_length=100, blank=True)
    community = models.CharField(max_length=50, default='public', blank=True)
    discovered_on = models.DateTimeField(auto_now_add=True)
    confirmed = models.BooleanField(default=False)
    status = models.CharField(max_length=50, default='Unknown')
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"[Discovered] {self.ip_address} - {self.hostname or 'N/A'} ({self.status})"

class Device(models.Model):
    """
    Official inventory of managed devices (after confirmation).
    """
    ip_address = models.GenericIPAddressField(protocol='IPv4', unique=True)
    hostname = models.CharField(max_length=100, blank=True)
    device_type = models.CharField(max_length=100, blank=True)
    vendor = models.CharField(max_length=100, blank=True)
    community = models.CharField(max_length=50, default='public', blank=True)
    contact = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=50, default='Unknown')
    last_seen = models.DateTimeField(default=now)

    @property
    def device_resourcelatest(self):
        return self.deviceresource_set.order_by('-timestamp').first()

    def __str__(self):
        return f"{self.hostname or self.ip_address}"


class NetworkInterface(models.Model):
    """
    Interfaces for each managed Device (populated by SNMP poll).
    """
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='interfaces')
    name = models.CharField(max_length=100)      # ifDescr
    status = models.CharField(max_length=50)     # ifOperStatus (e.g. "Up", "Down")

    last_in_octets = models.BigIntegerField(default=0)
    last_out_octets = models.BigIntegerField(default=0)
    last_polled = models.DateTimeField(auto_now=True)

    bandwidth_in = models.FloatField(default=0)  # in bps
    bandwidth_out = models.FloatField(default=0)
    utilization_in = models.FloatField(default=0)  # Percentage
    utilization_out = models.FloatField(default=0)

    def __str__(self):
        return f"{self.device.hostname} - {self.name} ({self.status})"

class DeviceResource(models.Model):
    """
    Stores historical resource usage for devices.
    """
    device = models.ForeignKey(Device, on_delete=models.CASCADE)  # Link to Device
    cpu_usage = models.FloatField(null=True, blank=True)
    mem_usage = models.FloatField(null=True, blank=True)
    timestamp = models.DateTimeField(default=now)  # Stores when the data was collected

    def __str__(self):
        return f"{self.device.hostname} - CPU: {self.cpu_usage}%, Mem: {self.mem_usage}%"

