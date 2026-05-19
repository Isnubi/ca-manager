"""
Background scheduler — runs the expiry digest email once a day at 08:00.
Initialised once by create_app(); safe with gunicorn --workers 1.
"""
import atexit
import logging

logger = logging.getLogger(__name__)
_scheduler = None


def init_scheduler(app):
    global _scheduler
    if _scheduler is not None:
        return

    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        func=lambda: _run_digest(app),
        trigger=CronTrigger(hour=8, minute=0),
        id='expiry_digest',
        replace_existing=True,
    )
    _scheduler.start()
    atexit.register(_shutdown)
    logger.info('Scheduler started — expiry digest job runs daily at 08:00')


def _shutdown():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


def _run_digest(app):
    try:
        with app.app_context():
            from app.blueprints.utils.mailer import send_expiry_digest
            sent, msg = send_expiry_digest()
            if sent:
                logger.info('Expiry digest: %s', msg)
            else:
                logger.debug('Expiry digest skipped: %s', msg)
    except Exception:
        logger.exception('Expiry digest job failed')
