import logging
import subprocess
from ipaddress import ip_network
from celery import shared_task
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd
)
from django.utils import timezone
from .models import Device, NetworkInterface, DiscoveredDevice, DeviceResource
from concurrent.futures import ThreadPoolExecutor, as_completed
from networkproject import settings
from django.core.mail import send_mail
from django.db import transaction

logger = logging.getLogger(__name__)


EXCLUDED_IPS = ["192.168.10.2", "192.168.10.4"]


def can_ping(ip, timeout=1):
    """
    Returns True if host responds to ping, else False.
    -W sets a timeout in seconds for each ping attempt.
    """
    cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return (result.returncode == 0)


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



# Common OIDs for SNMP
OIDS = {
    "sys_name": "1.3.6.1.2.1.1.5.0",        # Hostname
    "sys_descr": "1.3.6.1.2.1.1.1.0",       # Device type (Description)
    "sys_contact": "1.3.6.1.2.1.1.4.0",     # Admin contact
    "sys_location": "1.3.6.1.2.1.1.6.0",    # Device location
    "if_descr": "1.3.6.1.2.1.2.2.1.2",      # Interface name (ifDescr)
    "if_status": "1.3.6.1.2.1.2.2.1.8",     # Interface status (ifOperStatus)
    "if_speed": "1.3.6.1.2.1.2.2.1.5",      # interface speed
    "if_in_octets": "1.3.6.1.2.1.2.2.1.10", # interface incoming packet
    "if_out_octets": "1.3.6.1.2.1.2.2.1.16" # interface outgoing packet
}


def snmp_get(ip, community, oid):
    """Perform a single SNMP GET and return the value as a string."""
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161), timeout=2),
        ContextData(),
        ObjectType(ObjectIdentity(oid)) #this code specify which snmp object to retrive via oid
    )

    result= next(iterator)
    errorIndication, errorStatus, errorIndex, varBinds = result

    if errorIndication:
        return logger.error(f"SNMP GET error on {ip}: {errorIndication}")
    if errorStatus:
        return logger.error(f"SNMP GET status error on {ip}: {errorStatus.prettyPrint()}")
    
    if varBinds:
        for binding in varBinds:
            print("Varbind: ", binding)
        return varBinds[0][1].prettyPrint()
    else:
        return logger.error(f"SNMP varbinds error; {ip} ") 


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
    Poll SNMP data for a single device and update its details and interfaces when confirmation button is clicked.
    """
    logger.info(f"Polling SNMP data for {device.ip_address}...")
    # Get basic SNMP info
    sys_name = snmp_get(device.ip_address, community, OIDS["sys_name"])
    if sys_name:
        device.hostname = sys_name

    sys_descr = snmp_get(device.ip_address, community, OIDS["sys_descr"]) or "Unknown"
    sys_contact = snmp_get(device.ip_address, community, OIDS["sys_contact"]) or "Unavailable"
    sys_location = snmp_get(device.ip_address, community, OIDS["sys_location"]) or "Unknown"
    
    device.device_type = sys_descr
    device.contact = sys_contact
    device.location = sys_location
    device.last_seen = timezone.now()
    device.status = "Up"
    device.save()

    # Poll interface data
    iface_names = snmp_walk(device.ip_address, community, OIDS["if_descr"])
    iface_statuses = snmp_walk(device.ip_address, community, OIDS["if_status"])
    iface_speeds = snmp_walk(device.ip_address, community, OIDS["if_speed"])  # in bps

    in_octets = snmp_walk(device.ip_address, community, OIDS["if_in_octets"])
    out_octets = snmp_walk(device.ip_address, community, OIDS["if_out_octets"])

    current_time = timezone.now() # Timestamp for current polling

    if not iface_names or not iface_statuses or not iface_speeds:
        logger.warning(f"Failed to retrieve interface details for {device.ip_address}")
        return "SNMP polling failed"

    # Fetch previous polling data from the database
    previous_interfaces = {iface.name: iface for iface in NetworkInterface.objects.filter(device=device)}


    with transaction.atomic():
        for i in range(min(len(iface_names), len(iface_statuses), len(iface_speeds), len(in_octets), len(out_octets))):
            name = iface_names[i]
            status = "Up" if iface_statuses[i] == "1" else "Down"
            speed = int(iface_speeds[i]) if iface_speeds[i].isdigit() else 0  # bps
            in_bytes = int(in_octets[i])
            out_bytes = int(out_octets[i])

            # Retrieve previous data if available
            prev_data = previous_interfaces.get(name)

            logger.info(prev_data)

            if prev_data:
                time_diff = (current_time - prev_data.last_polled).total_seconds()

                # logger.info(time_diff)

                if time_diff > 0:

                    # Calculate Bandwidth Usage
                    delta_in = (in_bytes - prev_data.last_in_octets) * 8  # Convert bytes to bits
                    delta_out = (out_bytes - prev_data.last_out_octets) * 8

                    bandwidth_in_bps = delta_in / time_diff
                    bandwidth_out_bps = delta_out / time_diff

                    utilization_in = (bandwidth_in_bps / speed) * 100 if speed > 0 else 0
                    utilization_out = (bandwidth_out_bps / speed) * 100 if speed > 0 else 0
 
                    # logger.info(bandwidth_in_bps, bandwidth_out_bps, utilization_in, utilization_out)

                    # No previous data available, set bandwidth as 0 initially
                    NetworkInterface.objects.update_or_create(
                        device=device,
                        name=name,
                        defaults={
                            "status": status,
                            "bandwidth_in": bandwidth_in_bps,
                            "bandwidth_out": bandwidth_out_bps,
                            "utilization_in": utilization_in,
                            "utilization_out": utilization_out,
                            "last_in_octets": in_bytes,
     S                       "last_out_octets": out_bytes,
                            "last_polled": current_time,
                        }
                    )
                else:
                    logger.info("Error in time polling")
            else:
                # No previous data available, set bandwidth as 0 initially
                # Create a new interface record if one doesn't exist
                NetworkInterface.objects.update_or_create(
                                device=device,
                                name=name,
                                defaults={
                                    "status": status,
                                    "bandwidth_in": 0,
                                    "bandwidth_out": 0,
                                    "utilization_in": 0,
                                    "utilization_out": 0,
                                    "last_in_octets":in_bytes,
                                    "last_out_octets": out_bytes,
                                    "last_polled": current_time,}
                    )         

    summary_message = f"Polled SNMP data for {device.ip_address}: {len(iface_names)} interfaces. "
    
    interface_details = []
    for interface in NetworkInterface.objects.filter(device=device):
        interface_details.append(
            f"Interface {interface.name} {interface.status} "
            f"Bandwidth In: {interface.bandwidth_in} bps, "
            f"Bandwidth Out: {interface.bandwidth_out} bps, "
            f"Utilization In: {interface.utilization_in}%, "
            f"Utilization Out: {interface.utilization_out}%"
        )

    if interface_details:
        summary_message += "\n".join(interface_details)
    else:
        summary_message += "No interfaces found for this device."
    
    return summary_message

@shared_task
def update_snmp_data():
    """
    For each Device, check if it's reachable. If so, gather SNMP data, else mark it Down.
    """
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
        else:
            logger.warning(f"SNMP sys_name retrieval failed for {dev.ip_address}")
        
        if not dev.hostname:
            new_devices += 1
        
        # Call the common polling function to update SNMP data and interface records.
        poll_result = poll_device_snmp(dev, community=dev.community)
        devices_updated += 1

    summary_message = (
        f"\n{sys_name}\n"
        f"SNMP data collection complete. Polled {total_polled} devices. \n"
        f"Updated {devices_updated} devices. \n"
        f"New devices found: {new_devices}.\n"
        f"{poll_result}"
    )
    return summary_message


@shared_task
def check_device_resources():
    """
    Poll the device's CPU and memory usage via SNMP and check for alerts.
    Also check if the device or any interface is down.
    Returns an alert message if any conditions are met, otherwise None.
    """
    devices = Device.objects.all()
    results=[]
    


    CPU_OID = "1.3.6.1.4.1.9.2.1.57.0"      # Example: CPU utilization (percent)
    MEM_OID = "1.3.6.1.4.1.9.2.1.58.0"      # Example: Memory utilization (percent)
    community = "public"

    for device in devices:
        cpu_usage = None
        mem_usage = None
        alert_message = ""

    try:
        cpu_val = snmp_get(device.ip_address, community, CPU_OID)
        cpu_usage = float(cpu_val) if cpu_val else None
        print(f"CPU Usage for {device.hostname}: {cpu_usage}%")

    except Exception as e:
        logger.error(f"Error polling CPU for {device.ip_address}: {e}")

    try:
        mem_val = snmp_get(device.ip_address, community, MEM_OID)
        mem_usage = float(mem_val) if mem_val else None
        print(f"Memory Usage for {device.hostname}: {mem_usage}%")
    except Exception as e:
        logger.error(f"Error polling memory for {device.ip_address}: {e}")

    # Check CPU threshold
    if cpu_usage is not None and cpu_usage > 90:
        alert_message += f"High CPU usage: {cpu_usage}%.\n"
        #Pass device attributes, not the whole object
        send_email(device.ip_address, device.hostname, device.name, device.status)

    # Check Memory threshold
    if mem_usage is not None and mem_usage > 90:
        alert_message += f"High Memory usage: {mem_usage}%.\n"
        # Pass device attributes, not the whole object
        send_email(device.ip_address, device.hostname, device.name, device.status)

    DeviceResource.objects.create(
            device=device,
            cpu_usage=cpu_usage,
            mem_usage=mem_usage,
            timestamp=timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    results.append({
        "device": device.hostname,
        "cpu_usage": cpu_usage,
        "mem_usage": mem_usage,
        "timestamp" :timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    print("Task Execution Complete. Results:", results)

    return results


def send_email(device_ip,device_hostname,interface_name,interface_status):

    subject = f"Update on Device {device_hostname} : {device_ip}"
    message =(f"An SNMP trap was received indicating an interface Status.\n\n"
            f"Device IP: {device_ip}\n"
            f"Interface: {interface_name}\n"
            f"Status: {interface_status}\n")

    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [settings.ADMIN_EMAIL] 
    try:
        send_mail(subject, message, from_email, recipient_list)
        logger.info(f"Sent alert email for {device_hostname} {device_ip}")
    except Exception as e:
        logger.error(f"Error sending email for {device_ip}: {e}")