import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CTI.settings')

app = Celery('CTI')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'run-all-feeds-every-hour': {
        'task': 'threatintel.tasks.run_all_feeds',
        'schedule': crontab(minute=0),  # every hour
    },
    'run-cisa-kev-daily': {
        'task': 'threatintel.tasks.run_feed_threat',
        'schedule': crontab(hour=6, minute=0),  # every day at 6am
    },
}
