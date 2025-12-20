from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .alert_engine import AlertEngine

_scheduler = None

def start_scheduler(app):
    global _scheduler
    if _scheduler:
        return

    engine = AlertEngine()
    _scheduler = BackgroundScheduler(daemon=True)

    def job():
        with app.app_context():
            engine.run_once()

    _scheduler.add_job(job, IntervalTrigger(seconds=60), id="alert_engine", replace_existing=True)
    _scheduler.start()
