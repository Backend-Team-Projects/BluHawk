import traceback
from datetime import datetime


from rest_framework.response import Response
from rest_framework import status
from dashboard.models import ErrorLogs


def log_exception(
    e: Exception = None,
    response_data: dict = {"message": "Internal Server Error"},
    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, error:str = None, error_trace: str = None
) :
    try:
        print(f"error {e}", e.__traceback__ if e else None)
        if e is not None:
            error_trace = traceback.format_exc()
            error_log = {
                "error": f"{e}",
                "error_trace": f"{error_trace}",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        else:
            error_log = {
                "error": f"{error}",
                "error_trace": f"{error_trace}",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            
        print(f"error_log {error_log}")

        ErrorLogs.objects.create(
            error=error_log,
            updated_at=datetime.now(),
        )

        return Response(
            response_data,
            status=status_code,
        )
    except Exception as e:
        print(f"Error logging failed: {e}")
        return Response(
            {"message": "Internal Server Error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )