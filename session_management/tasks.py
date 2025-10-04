import subprocess
import logging
import os
from datetime import timedelta
from django.utils.timezone import now
from django.conf import settings
from BluHawk.models import Scanlog, Organization
from celery import shared_task

# ----------------------------
# Logger setup
# ----------------------------
logger = logging.getLogger("scanlog_cleanup")
if not logger.handlers:
    handler = logging.FileHandler(os.path.join(settings.BASE_DIR, "scanlog_cleanup.log"))
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# ----------------------------
# 1️⃣ Backup PostgreSQL DB via pg_dump + Restic
# ----------------------------
def backup_db_with_restic():
    try:
        # Directory to store DB dumps
        db_dump_dir = "/path/to/db_dumps"
        os.makedirs(db_dump_dir, exist_ok=True)

        # PostgreSQL DB settings from Django
        db_name = settings.DATABASES['default']['NAME']
        db_user = settings.DATABASES['default']['USER']
        db_password = settings.DATABASES['default']['PASSWORD']
        db_host = settings.DATABASES['default']['HOST']
        db_port = settings.DATABASES['default']['PORT']

        # Dump file path
        dump_file = os.path.join(db_dump_dir, f"{db_name}_{now().strftime('%Y%m%d%H%M%S')}.sql")

        env = os.environ.copy()
        env["POSTGRESQL_PASSWORD"] = db_password

        # Run pg_dump
        subprocess.run([
            "pg_dump",
            "-h", db_host,
            "-p", str(db_port),
            "-U", db_user,
            "-F", "c",       # custom format
            "-f", dump_file,
            db_name
        ], check=True, env=env)

        logger.info(f"Database dumped successfully to {dump_file}")

        # Run Restic backup
        subprocess.run([
            "restic",
            "backup",
            db_dump_dir,
            "--tag", "scanlog_backup"
        ], check=True)

        logger.info("Database dump successfully backed up via Restic.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Backup failed: {str(e)}")


# ----------------------------
# 2️⃣ Delete Old Scanlogs
# ----------------------------
def delete_old_scanlogs(retention_days=365):
    try:
        # Backup first
        backup_db_with_restic()

        # Delete logs older than retention_days per organization
        for org in Organization.objects.all():
            retention = getattr(org, 'retention_days', retention_days)
            cutoff = now() - timedelta(days=retention)
            deleted_count, _ = Scanlog.objects.filter(organization=org, timestamp__lt=cutoff).delete()
            logger.info(f"Deleted {deleted_count} scanlogs for organization '{org.name}' older than {retention} days.")

    except Exception as e:
        logger.error(f"Error deleting old scanlogs: {str(e)}")


# ----------------------------
# 3️⃣ Celery Task Wrapper
# ----------------------------
@shared_task(name="scanlogs.tasks.cleanup_scanlogs")
def cleanup_scanlogs_task():
    """
    Celery task to backup DB and delete old scanlogs.
    """
    delete_old_scanlogs()
