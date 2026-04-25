import os
from celery import Celery

# Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CTI.settings')

# Create Celery app
app = Celery('CTI')

# Load Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks
app.autodiscover_tasks()


# ⏱️ BEAT SCHEDULE (PUT IT HERE)
app.conf.beat_schedule = {
    "run-all-feeds-every-5-min": {
        "task": "threatintel.tasks.run_all_feeds",
        "schedule": 300.0,  # 5 minutes
    },
}