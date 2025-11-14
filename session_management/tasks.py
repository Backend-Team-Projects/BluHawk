# import subprocess
# import logging
# import os
# from datetime import timedelta
# from django.utils.timezone import now
# from django.conf import settings
# from session_management.models import Scanlog, Organization
# from celery import shared_task
# from BluHawk.load_env import *

# # ----------------------------
# # Logger setup
# # ----------------------------
# logger = logging.getLogger("scanlog_cleanup")
# if not logger.handlers:
#     handler = logging.FileHandler(os.path.join(settings.BASE_DIR, "scanlog_cleanup.log"))
#     handler.setLevel(logging.INFO)
#     formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)


# # ----------------------------
# # 1️⃣ Backup PostgreSQL DB via pg_dump + Restic
# # ----------------------------
# def backup_db_with_restic():
#     try:
#         # Directory to store DB dumps
#         db_dump_dir = "/home/poorna/BluHawk/backups/db_dumps"
#         os.makedirs(db_dump_dir, exist_ok=True)

#         # PostgreSQL DB settings from Django
#         db_name = settings.DATABASES['default']['NAME']
#         db_user = settings.DATABASES['default']['USER']
#         db_password = settings.DATABASES['default']['PASSWORD']
#         db_host = settings.DATABASES['default']['HOST']
#         db_port = settings.DATABASES['default']['PORT']

#         # Dump file path
#         dump_file = os.path.join(db_dump_dir, f"{db_name}_{now().strftime('%Y%m%d%H%M%S')}.sql")

#         env = os.environ.copy()
#         env["PGPASSWORD"] = db_password

#         # Run pg_dump
#         subprocess.run([
#             "pg_dump",
#             "-h", db_host,
#             "-p", str(db_port),
#             "-U", db_user,
#             "-F", "c",       # custom format
#             "-f", dump_file,
#             db_name
#         ], check=True, env=env)

#         logger.info(f"Database dumped successfully to {dump_file}")

#         # Run Restic backup
#         subprocess.run([
#             "restic",
#             "backup",
#             db_dump_dir,
#             "--tag", "scanlog_backup"
#         ], check=True)

#         logger.info("Database dump successfully backed up via Restic.")

#     except subprocess.CalledProcessError as e:
#         logger.error(f"Backup failed: {str(e)}")


# # ----------------------------
# # 2️⃣ Delete Old Scanlogs
# # ----------------------------
# def delete_old_scanlogs(retention_days=365):
#     try:
#         # Backup first
#         backup_db_with_restic()

#         # Delete logs older than retention_days per organization
#         for org in Organization.objects.all():
#             retention = getattr(org, 'retention_days', retention_days)
#             cutoff = now() - timedelta(days=retention)
#             deleted_count, _ = Scanlog.objects.filter(organization=org, timestamp__lt=cutoff).delete()
#             logger.info(f"Deleted {deleted_count} scanlogs for organization '{org.name}' older than {retention} days.")

#     except Exception as e:
#         logger.error(f"Error deleting old scanlogs: {str(e)}")


# # ----------------------------
# # 3️⃣ Celery Task Wrapper
# # ----------------------------
# @shared_task(name="scanlogs.tasks.cleanup_scanlogs")
# def cleanup_scanlogs_task():
#     """
#     Celery task to backup DB and delete old scanlogs.
#     """
#     delete_old_scanlogs()




# import subprocess
# import logging
# import os
# from datetime import timedelta, datetime
# from django.utils.timezone import now
# from django.conf import settings
# from session_management.models import Scanlog, Organization
# from celery import shared_task

# # ----------------------------
# # Config (adjust as needed)
# # ----------------------------
# DB_DUMP_DIR = "/home/poorna/BluHawk/backups/db_dumps"
# LOCAL_DUMP_RETENTION_DAYS = 14  # remove local dumps older than this after successful restic
# RESTIC_TAG = "scanlog_backup"

# # ----------------------------
# # Logger setup
# # ----------------------------
# logger = logging.getLogger("scanlog_cleanup")
# if not logger.handlers:
#     handler = logging.FileHandler(os.path.join(settings.BASE_DIR, "scanlog_cleanup.log"))
#     handler.setLevel(logging.INFO)
#     formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)


# # ----------------------------
# # Backup PostgreSQL DB via pg_dump + Restic
# # ----------------------------
# def backup_db_with_restic():
#     """Create DB dump and back it up via restic. Raise on failure."""
#     # sanity checks for Restic env
#     restic_repo = os.environ.get("RESTIC_REPOSITORY")
#     restic_password = os.environ.get("RESTIC_PASSWORD")
#     if not restic_repo or not restic_password:
#         raise RuntimeError("RESTIC_REPOSITORY and RESTIC_PASSWORD must be set in environment for restic backups.")

#     os.makedirs(DB_DUMP_DIR, exist_ok=True)

#     db_name = settings.DATABASES['default']['NAME']
#     db_user = settings.DATABASES['default']['USER']
#     db_password = settings.DATABASES['default']['PASSWORD']
#     db_host = settings.DATABASES['default'].get('HOST', 'localhost') or 'localhost'
#     db_port = settings.DATABASES['default'].get('PORT', 5432) or 5432

#     dump_file = os.path.join(DB_DUMP_DIR, f"{db_name}_{now().strftime('%Y%m%d%H%M%S')}.sql")

#     env = os.environ.copy()
#     env["PGPASSWORD"] = db_password

#     try:
#         # run pg_dump
#         subprocess.run([
#             "pg_dump",
#             "-h", db_host,
#             "-p", str(db_port),
#             "-U", db_user,
#             "-F", "c",       # custom format
#             "-f", dump_file,
#             db_name
#         ], check=True, env=env)
#         logger.info(f"Database dumped successfully to {dump_file}")

#         # restic backup
#         subprocess.run([
#             "restic",
#             "backup",
#             DB_DUMP_DIR,
#             "--tag", RESTIC_TAG
#         ], check=True, env=os.environ.copy())
#         logger.info("Database dump successfully backed up via Restic.")

#         # prune local dump files older than LOCAL_DUMP_RETENTION_DAYS
#         prune_local_dumps(DB_DUMP_DIR, LOCAL_DUMP_RETENTION_DAYS)

#     except subprocess.CalledProcessError as e:
#         logger.error(f"Command failed during backup: {e}")
#         # re-raise so caller can stop deletion
#         raise
#     except Exception:
#         logger.exception("Unexpected error during backup.")
#         raise


# def prune_local_dumps(dirpath: str, keep_days: int):
#     """Remove local DB dumps older than keep_days (best-effort)."""
#     try:
#         cutoff_dt = datetime.utcnow() - timedelta(days=keep_days)
#         for fname in os.listdir(dirpath):
#             fpath = os.path.join(dirpath, fname)
#             if not os.path.isfile(fpath):
#                 continue
#             # use modification time (UTC)
#             mtime = datetime.utcfromtimestamp(os.path.getmtime(fpath))
#             if mtime < cutoff_dt:
#                 try:
#                     os.remove(fpath)
#                     logger.info(f"Removed old local dump: {fpath}")
#                 except Exception:
#                     logger.exception(f"Failed to remove local dump: {fpath}")
#     except Exception:
#         logger.exception("Failed to prune local dumps.")


# # ----------------------------
# # Delete Old Scanlogs
# # ----------------------------
# def delete_old_scanlogs(retention_days=365):
#     """
#     Backup database first (raises on failure), then delete old scanlogs per org.
#     """
#     try:
#         backup_db_with_restic()
#     except Exception as e:
#         logger.error(f"Backup failed, aborting deletion: {e}")
#         return  # abort deletion if backup failed

#     # proceed with deletion
#     for org in Organization.objects.all():
#         try:
#             retention = getattr(org, 'retention_days', retention_days)
#             cutoff = now() - timedelta(days=retention)
#             deleted_count, _ = Scanlog.objects.filter(organization=org, timestamp__lt=cutoff).delete()
#             logger.info(f"Deleted {deleted_count} scanlogs for organization '{org.name}' older than {retention} days.")
#         except Exception:
#             logger.exception(f"Failed deleting scanlogs for organization {getattr(org, 'name', org.id)}")


# # ----------------------------
# # Celery Task Wrapper
# # ----------------------------
# @shared_task(name="scanlogs.tasks.cleanup_scanlogs")
# def cleanup_scanlogs_task():
#     delete_old_scanlogs()


