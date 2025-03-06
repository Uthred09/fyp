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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    logger.info("Received SNMP Trap")
    
    # Get the peer address (device IP) from the transport info tuple.
    try:
        transport_info = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
        # transport_info: (transportDomain, (device_ip, device_port))
        _, peer_addr = transport_info
        device_ip, device_port = peer_addr
        logger.info(f"Trap sent from {device_ip}:{device_port}")
    except Exception as e:
        logger.error(f"Could not get peer address: {e}")
        return

    # Convert varBinds into a dictionary for easier lookup
    trap_data = {}
    trap_type = None  # We'll capture the trap type from OID 1.3.6.1.6.3.1.1.4.1.0
    for oid, val in varBinds:
        oid_str = oid.prettyPrint()
        val_str = val.prettyPrint()
        trap_data[oid_str] = val_str
        logger.info(f"{oid_str} = {val_str}")
        if oid_str == "1.3.6.1.6.3.1.1.4.1.0":
            trap_type = val_str

    # Extract the interface name from ifDescr OID: 1.3.6.1.2.1.2.2.1.2.X
    interface_name = None
    for oid_str, val_str in trap_data.items():
        if oid_str.startswith("1.3.6.1.2.1.2.2.1.2."):
            interface_name = val_str
            break

    # Try to get a Cisco-specific interface status first, if present.
    interface_status = None
    for oid_str, val_str in trap_data.items():
        if oid_str.startswith("1.3.6.1.4.1.9.2.2.1.1.20."):
            interface_status = val_str
            break

    # If no explicit interface status, use the trap type as fallback.
    if not interface_status and trap_type:
        # linkDown trap is 1.3.6.1.6.3.1.1.5.3, linkUp trap is 1.3.6.1.6.3.1.1.5.4
        if trap_type == "1.3.6.1.6.3.1.1.5.3":
            interface_status = "Down"
        elif trap_type == "1.3.6.1.6.3.1.1.5.4":
            interface_status = "Up"
        else:
            interface_status = "Unknown"

    if interface_name and interface_status:
        try:
            # Import models (ensure Django is set up already)
            from dashboardapp.models import Device, NetworkInterface
            device = Device.objects.get(ip_address=device_ip)
            iface = NetworkInterface.objects.filter(device=device, name=interface_name).first()
            if iface:
                iface.status = interface_status
                iface.save()
                logger.info(f"Updated interface '{interface_name}' on device {device_ip} to {interface_status}")
            else:
                logger.warning(f"No interface '{interface_name}' found for device {device_ip}")
        except Device.DoesNotExist:
            logger.warning(f"No device found with IP {device_ip}")
    else:
        logger.info("Trap did not contain recognized interface name or status.")
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
