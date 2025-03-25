import os
from celery import Celery
from datetime import timedelta

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'networkproject.settings')

app = Celery('networkproject')

# load configuration from django settings and the namesapce celery means anything related to celery must start with 
# celery in setting.py
app.config_from_object('django.conf:settings', namespace='CELERY')

# Discover tasks in all registered Django apps
app.autodiscover_tasks()

#Celery beat schedule (for periodic tasks)
app.conf.beat_schedule = {
    'poll-snmp-every-5-min': {
        'task': 'dashboardapp.tasks.update_snmp_data',
        'schedule': 60.0,  # 300 seconds = 5 minutes
    },
    'check_device_resources-every-30-second':{
        'task':'dashboardapp.tasks.check_device_resources',
        'schedule':30.0,
    }
}
