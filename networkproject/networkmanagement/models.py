from django.db import models
from django.utils.timezone import now
from dashboardapp.models import Device  # Import from the monitoring app

class ConfigurationTask(models.Model):
    """
    Stores configuration tasks that will be executed via Ansible.
    """
    TASK_CHOICES = [
        ('PING', 'Ping Device'),
        ('HOSTNAME', 'Change Hostname'),
        ('VLAN', 'Configure VLAN'),
        ('ACL', 'Implement ACL'),
    ]
    
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='config_tasks')
    task_type = models.CharField(max_length=20, choices=TASK_CHOICES)
    parameters = models.JSONField(blank=True, null=True)  # Stores task-specific data (e.g., VLAN ID)
    status = models.CharField(max_length=20, default='Pending')  # Pending, Running, Completed, Failed
    created_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.device.hostname} - {self.get_task_type_display()} ({self.status})"


class ExecutionLog(models.Model):
    """
    Logs the execution of each Ansible task.
    """
    task = models.ForeignKey(ConfigurationTask, on_delete=models.CASCADE, related_name='logs')
    output = models.TextField(blank=True)  # Stores Ansible output/logs
    status = models.CharField(max_length=20, default='Pending')  # Success, Failed
    executed_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Task: {self.task.id} - {self.status} ({self.executed_at})"
