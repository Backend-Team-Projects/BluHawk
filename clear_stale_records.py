from django.utils.timezone import now
from attack_surface.models import AttackSurfaceScan
import json

# Delete records with serialization errors
AttackSurfaceScan.objects.filter(status="error", jsondata__contains="Object of type datetime is not JSON serializable").delete()

# Alternatively, update records to a valid state
for record in AttackSurfaceScan.objects.filter(status="error"):
    try:
        json.dumps(record.jsondata)  # Test serialization
    except TypeError:
        record.jsondata = {"error": "Invalid data, scan will be retried"}
        record.scanned_at = now()
        record.save()

print("Stale records cleared or updated.")