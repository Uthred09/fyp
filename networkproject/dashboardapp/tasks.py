import logging
import subprocess
from ipaddress import ip_network
from celery import shared_task
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd
)
from django.utils import timezone
from .models import Device, NetworkInterface, DiscoveredDevice
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger(__name__)

# Common OIDs for SNMP
OIDS = {
    "sys_name": "1.3.6.1.2.1.1.5.0",       # Hostname
    "sys_descr": "1.3.6.1.2.1.1.1.0",      # Device type (Description)
    "sys_contact": "1.3.6.1.2.1.1.4.0",    # Admin contact
    "sys_location": "1.3.6.1.2.1.1.6.0",   # Device location
    "if_descr": "1.3.6.1.2.1.2.2.1.2",     # Interface name (ifDescr)
    "if_status": "1.3.6.1.2.1.2.2.1.8",    # Interface status (ifOperStatus)
}


def snmp_get(ip, community, oid):
    """Perform a single SNMP GET and return the value as a string."""
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        logger.error(f"SNMP GET error on {ip}: {errorIndication}")
        return None
    if errorStatus:
        logger.error(f"SNMP GET status error on {ip}: {errorStatus.prettyPrint()}")
        return None
    return varBinds[0][1].prettyPrint() if varBinds else None


def snmp_walk(ip, community, oid):
    """Walk an SNMP table for the given OID, returning a list of values."""
    results = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication:
            logger.error(f"SNMP walk error on {ip}: {errorIndication}")
            break
        elif errorStatus:
            logger.error(f"SNMP walk status error on {ip}: {errorStatus.prettyPrint()}")
            break
        else:
            # varBinds is a list of tuples, each with (OID, Value)
            results.append(varBinds[0][1].prettyPrint())
    return results


def poll_device_snmp(device, community='public'):
    """
    Poll SNMP data for a single device and update its details and interfaces.
    Uses your existing snmp_get and snmp_walk functions.
    """
    logger.info(f"Starting SNMP poll for device {device.ip_address} (ID: {device.id})")
    # Get basic SNMP info
    sys_name = snmp_get(device.ip_address, community, "1.3.6.1.2.1.1.5.0")
    if sys_name:
        device.hostname = sys_name

    sys_descr = snmp_get(device.ip_address, community, "1.3.6.1.2.1.1.1.0") or "Unknown"
    sys_contact = snmp_get(device.ip_address, community, "1.3.6.1.2.1.1.4.0") or "Unavailable"
    sys_location = snmp_get(device.ip_address, community, "1.3.6.1.2.1.1.6.0") or "Unknown"
    
    device.device_type = sys_descr
    device.contact = sys_contact
    device.location = sys_location
    device.last_seen = timezone.now()
    device.status = "Up"
    device.save()

    # Poll interface data
    iface_names = snmp_walk(device.ip_address, community, "1.3.6.1.2.1.2.2.1.2")
    iface_statuses = snmp_walk(device.ip_address, community, "1.3.6.1.2.1.2.2.1.8")

    # Clear out old interface data for the device
    NetworkInterface.objects.filter(device=device).delete()

    # Create new interface records
    for i in range(min(len(iface_names), len(iface_statuses))):
        name = iface_names[i]
        status_val = iface_statuses[i]
        status_str = "Up" if status_val == "1" else "Down"
        NetworkInterface.objects.create(device=device, name=name, status=status_str)
    
    logger.info(f"Polled SNMP data for {device.ip_address}: found {len(iface_names)} interfaces")
    return f"Polled {len(iface_names)} interfaces"

def can_ping(ip, timeout=1):
    """
    Returns True if host responds to ping, else False.
    -W sets a timeout in seconds for each ping attempt.
    """
    cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return (result.returncode == 0)



EXCLUDED_IPS = ["192.168.10.2", "192.168.10.4"]
def scan_subnet(subnet="192.168.10.0/28", community="public"):
    """
    1) Ping all IPs in `subnet` concurrently.
    2) For responsive hosts, perform a minimal SNMP get (sysName) to update discovered device info.
    3) Mark previously discovered unresponsive devices as 'Offline' if not confirmed.
    """
    net = ip_network(subnet)
    responding_ips = set()

    # Create a ThreadPoolExecutor for concurrent pinging
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Submit ping tasks for all hosts not in the EXCLUDED_IPS list
        future_to_ip = {
            executor.submit(can_ping, str(ip), 2): str(ip)
            for ip in net.hosts() if str(ip) not in EXCLUDED_IPS
        }
        
        # Process each future as they complete
        for future in as_completed(future_to_ip):
            ip_str = future_to_ip[future]
            try:
                if future.result():
                    responding_ips.add(ip_str)
                    # Retrieve sys_name from SNMP; you could also make this call concurrent if needed.
                    sys_name = snmp_get(ip_str, community, OIDS["sys_name"]) or ""
                    
                    # Create or update discovered device
                    DiscoveredDevice.objects.update_or_create(
                        ip_address=ip_str,
                        defaults={
                            "hostname": sys_name,
                            "community": community,
                            "status": "Online",
                            "last_seen": timezone.now(),
                        }
                    )
            except Exception as exc:
                logger.error(f"Error scanning {ip_str}: {exc}")

    # Mark devices as Offline if they are no longer responding (and are not confirmed)
    for dd in DiscoveredDevice.objects.filter(confirmed=False):
        if dd.ip_address not in responding_ips:
            dd.status = "Offline"
            dd.save()
    
    logger.info(f"Scanning subnet {subnet} with community {community}")
    return f"Scan completed. Found {len(responding_ips)} responding IP(s)."

@shared_task
def update_snmp_data():
    """
    For each Device, check if it's reachable. If so, gather SNMP data, else mark it Down.
    """
    
    OIDS = {
        "sys_name": "1.3.6.1.2.1.1.5.0",
        "sys_descr": "1.3.6.1.2.1.1.1.0",
        "sys_contact": "1.3.6.1.2.1.1.4.0",
        "sys_location": "1.3.6.1.2.1.1.6.0",
        "if_descr": "1.3.6.1.2.1.2.2.1.2",
        "if_status": "1.3.6.1.2.1.2.2.1.8",
    }

    total_polled = 0
    devices_updated = 0
    new_devices = 0

    for dev in Device.objects.all():
        if dev.ip_address in EXCLUDED_IPS:
            continue
        
        total_polled += 1

        if not can_ping(dev.ip_address):
            dev.status = "Down"
            dev.save()
            NetworkInterface.objects.filter(device=dev).update(status="Down")
            continue

        # Attempt minimal SNMP
        sys_name = snmp_get(dev.ip_address, dev.community, OIDS["sys_name"])
        if not sys_name:
            dev.status = "Down"
            dev.save()
            continue
        
        if not dev.hostname:
            new_devices += 1

        # If we get here, the device is Up
        dev.status = "Up"
        dev.hostname = sys_name

        # sysDescr, sysContact, sysLocation
        sys_descr = snmp_get(dev.ip_address, dev.community, OIDS["sys_descr"]) or "Unknown"
        sys_contact = snmp_get(dev.ip_address, dev.community, OIDS["sys_contact"]) or "Unavailable"
        sys_location = snmp_get(dev.ip_address, dev.community, OIDS["sys_location"]) or "Unknown"

        dev.device_type = sys_descr
        dev.contact = sys_contact
        dev.location = sys_location
        dev.last_seen = timezone.now()
        dev.save()

        # Now fetch interface data
        # We'll assume you have a snmp_walk function
        iface_names = snmp_walk(dev.ip_address, dev.community, OIDS["if_descr"])
        iface_statuses = snmp_walk(dev.ip_address, dev.community, OIDS["if_status"])

        # Clear old interface records
        NetworkInterface.objects.filter(device=dev).delete()

        # Recreate
        for i in range(min(len(iface_names), len(iface_statuses))):
            name = iface_names[i]
            status_val = iface_statuses[i]
            status_str = "Up" if status_val == "1" else "Down"
            NetworkInterface.objects.create(device=dev, name=name, status=status_str)

        devices_updated += 1
        

    summary_message = (
        f"SNMP data collection complete. Polled {total_polled} devices. "
        f"Updated {devices_updated} devices. "
        f"New devices found: {new_devices}."
    )
    return summary_message