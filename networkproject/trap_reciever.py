import os
import logging

# If you're running this as a standalone script but want Django's models:
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "networkproject.settings")
import django
django.setup()

from pysnmp.hlapi.asyncore import SnmpEngine, CommunityData, UdpTransportTarget, ContextData
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.entity import config
from pysnmp.hlapi.asyncore.transport import udp
from dashboardapp.models import Device, NetworkInterface

from dashboardapp.tasks import send_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global OID Variables
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
IFDESCR_OID_PREFIX = "1.3.6.1.2.1.2.2.1.2."
IFSTATUS_OID_PREFIX = "1.3.6.1.4.1.9.2.2.1.1.20."
LINK_DOWN_TRAP_OID = "1.3.6.1.6.3.1.1.5.3"
LINK_UP_TRAP_OID = "1.3.6.1.6.3.1.1.5.4"


def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    
    
    logger.info("Received SNMP Trap")
    
    # Get the peer address (device IP) from the transport info tuple.
    try:
        transport_info = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
        _, peer_addr = transport_info
        device_ip, device_port = peer_addr
        logger.info(f"Trap sent from {device_ip}:{device_port}")
    except Exception as e:
        logger.error(f"Could not get peer address: {e}")
        return

    device = Device.objects.get(ip_address=device_ip)  # Query database
    device_hostname = device.hostname

    # Convert varBinds into a dictionary for easier lookup
    trap_data = {}
    trap_type = None  # Capture the trap type
    for oid, val in varBinds:
        oid_str = oid.prettyPrint()
        val_str = val.prettyPrint()
        trap_data[oid_str] = val_str
        print(f"OID: {oid_str} = Value: {val_str}")
        if oid_str == SNMP_TRAP_OID:
            trap_type = val_str

    print(trap_data)
    
    # Extract the interface name
    interface_name = None
    for oid_str, val_str in trap_data.items():
        if oid_str.startswith(IFDESCR_OID_PREFIX):
            interface_name = val_str
            print(interface_name)
            break

    # Extract Cisco-specific interface status
    interface_status = None
    for oid_str, val_str in trap_data.items():
        if oid_str.startswith(IFSTATUS_OID_PREFIX):
            interface_status = val_str
            print(interface_status)
            break

    # Use the trap type as fallback if no explicit interface status is found
    if not interface_status and trap_type:
        if trap_type == LINK_DOWN_TRAP_OID:
            interface_status = "Down"
        elif trap_type == LINK_UP_TRAP_OID:
            interface_status = "Up"
        else:
            interface_status = "Unknown"
    
    if interface_name and interface_status:
        try:
            device = Device.objects.get(ip_address=device_ip)
            iface = NetworkInterface.objects.filter(device=device, name=interface_name).first()
            if iface:
                iface.status = interface_status
                iface.save()
                print(f"Updated interface '{interface_name}' on device {device_ip} to {interface_status}")
            else:
                print(f"No interface '{interface_name}' found for device {device_ip}")
        except Device.DoesNotExist:
            print(f"No device found with IP {device_ip}")
    else:
        print("Trap did not contain recognized interface name or status.")

    send_email(device_ip,device_hostname,interface_name,interface_status)
    return

def run_snmp_trap_receiver():
    """
    Sets up and starts the SNMP trap receiver.
    It listens on UDP port 162 for traps with community 'public'.
    """
    snmpEngine = SnmpEngine()

    # Configure transport endpoint: listen on UDP/IPv4, port 162
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    )

    # Configure SNMPv2c community settings
    config.addV1System(snmpEngine, 'my-area', 'public')

    # Register our callback function for handling incoming traps
    ntfrcv.NotificationReceiver(snmpEngine, trap_callback)

    logger.info("SNMP Trap Receiver is running on UDP port 162...")
    try:
        # Start job that never ends so the trap receiver stays active
        snmpEngine.transportDispatcher.jobStarted(1)
        snmpEngine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        snmpEngine.transportDispatcher.closeDispatcher()
        logger.info("SNMP Trap Receiver stopped.")


if __name__ == '__main__':
    run_snmp_trap_receiver()
