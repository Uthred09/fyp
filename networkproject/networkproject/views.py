import subprocess
from django.shortcuts import render

def run_ansible_playbook():
    """Function to execute the Ansible playbook."""
    result = subprocess.run(
        ["ansible-playbook", "/home/kali/Desktop/fyp/ansible/playbook.yml"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout, result.stderr


def dashboard_view(request):
    """View to display data from Ansible."""
    stdout, stderr = run_ansible_playbook()
    return render(request, 'monitoring/dashboard.html', {
        "stdout": stdout,  # Ansible output
        "stderr": stderr   # Any errors
    })

