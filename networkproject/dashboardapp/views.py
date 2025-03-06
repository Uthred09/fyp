from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from .tasks import scan_subnet
from .tasks import update_snmp_data, poll_device_snmp
from .models import Device, DiscoveredDevice
from django.http import JsonResponse
from dashboardapp.tasks import scan_subnet


@login_required
def dashboard_view(request):
    # Show all main devices & interfaces
    devices = Device.objects.prefetch_related('interfaces').all()
    return render(request, "dashboardapp/dashboard.html", {"devices": devices})


def scan_network_view(request):
    if request.method == 'POST':
        # Trigger the Celery task
        scan_subnet("192.168.10.0/28", "public")
        messages.success(request, "Scan triggered")
        # Redirect to the dashboard (or any other page you prefer)
        return redirect(reverse('discovered_list'))
    # For non-POST requests, redirect as well
    return redirect(reverse('discovered_list'))


def discovered_list(request):
    # Show any unconfirmed DiscoveredDevices
    discovered = DiscoveredDevice.objects.filter(confirmed=False)
    return render(request, "dashboardapp/discovered_list.html", {"discovered": discovered})

def confirm_discovered_device(request, pk):
    if request.method == 'POST':
        disc_dev = get_object_or_404(DiscoveredDevice, pk=pk)
        # create or update main Device
        device, created = Device.objects.update_or_create(
            ip_address=disc_dev.ip_address,
            defaults={
                "hostname": disc_dev.hostname,
                "community": disc_dev.community,
                "status": disc_dev.status,  # carry over 'Online' or 'Offline'
                "last_seen": disc_dev.last_seen,
            }
        )
        disc_dev.confirmed = True
        disc_dev.save()

        poll_device_snmp(device)
        
        return redirect('discovered_list')
    # if GET, we can just redirect or show a minimal confirmation page
    return redirect('discovered_list')


def delete_discovered_device(request, pk):
    """
    Allows admin to remove an unwanted discovered device entry.
    """
    if request.method == 'POST':
        disc_dev = get_object_or_404(DiscoveredDevice, pk=pk)
        disc_dev.delete()
        messages.success(request, f"Discovered device {disc_dev.ip_address} deleted.")
        return redirect('discovered_list')
    return redirect('discovered_list')



def delete_device_view(request, pk):
    """
    Deletes a device from the database.
    """
    device = get_object_or_404(Device, pk=pk)

    if request.method == 'POST':
        device.delete()
          # or wherever you want to redirect
        discovered_device = DiscoveredDevice.objects.filter(ip_address=device.ip_address).first()
        if discovered_device:
            discovered_device.confirmed = False
            discovered_device.save()
    # If someone hits this URL with GET, you can either show a confirmation page or redirect:
    messages.error(request, "Invalid request method.")
    return redirect('dashboard')

