from django.contrib import admin
from .models import ConfigurationTask, ExecutionLog

admin.site.register(ConfigurationTask)
admin.site.register(ExecutionLog)
