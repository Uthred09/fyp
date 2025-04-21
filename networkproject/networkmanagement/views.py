from django.shortcuts import render
import ansible_runner
from django.http import JsonResponse
from dashboardapp.models import Device
import os

def network_management_home(request):
    devices = Device.objects.all()
    return render(request, "networkmanagement/main.html", {"devices": devices})


BASE_DIR = "/home/kali/Desktop/fyp/networkproject/networkmanagement/ansible"
TMP_DIR = os.path.join(BASE_DIR, "tmp")

def run_ansible_task(ip, playbook_name, extravars=None):
    inventory_path = os.path.join(TMP_DIR, "inventory.ini")
    with open(inventory_path, "w") as f:
        f.write("[all]\n")
        f.write(f"{ip} ansible_user=admin ansible_password=cisco ansible_connection=network_cli ansible_network_os=ios ansible_become=yes ansible_become_method=enable\n")

    result = ansible_runner.run(
        private_data_dir=BASE_DIR,
        playbook=playbook_name,
        inventory=inventory_path,
        extravars=extravars or {}
    )

    os.remove(inventory_path)

    if result.rc == 0:
        return {"status": "success", "message": "Task completed successfully"}
    else:
        return {"status": "fail", "message": "Task failed"}

# API views
def ping_device(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        target_ip = request.POST.get("target")
        return JsonResponse(run_ansible_task(ip, "ping.yml", {"target_ip": target_ip}))


def change_hostname(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        hostname = request.POST.get("hostname")
        return JsonResponse(run_ansible_task(ip, "change_hostname.yml", {"new_hostname": hostname}))

def set_banner_motd(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        banner = request.POST.get("banner")
        return JsonResponse(run_ansible_task(ip, "banner.yml", {"banner": banner}))

def set_console_password(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        password = request.POST.get("console_password")
        return JsonResponse(run_ansible_task(ip, "console_password.yml", {"console_password": password}))

def set_vty_password(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        password = request.POST.get("password")
        return JsonResponse(run_ansible_task(ip, "vty_password.yml", {"vty_password": password}))

def create_vlan(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        vlan_id = request.POST.get("vlan_id")
        vlan_name = request.POST.get("vlan_name")
        interface = request.POST.get("interface")
        mode = request.POST.get("mode")  # access or trunk

        extra_vars = {
            "vlan_id": vlan_id,
            "vlan_name": vlan_name,
            "interface": interface,
            "mode": mode
        }

        return JsonResponse(run_ansible_task(ip, "vlan_config.yml", extra_vars))


def apply_acl(request):
    if request.method == 'POST':
        ip = request.POST.get('ip')
        acl_rules = request.POST.get('acl_rules')  # Example: a list or string of ACL rules
        device = Device.objects.get(ip_address=ip)

        # Check if the device is a router
        if device.device_type == 'router':
            # Run the Ansible playbook with the ACL rules
            result = run_ansible_task(ip, "apply_acl.yml", {"acl_rules": acl_rules})
            return JsonResponse({'status': 'success', 'message': 'ACL applied successfully!'})
        else:
            return JsonResponse({'status': 'failure', 'message': 'ACL cannot be applied to switches.'})