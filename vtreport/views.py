from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import httpx
import os
from rest_framework.views import APIView



# @method_decorator(csrf_exempt, name='dispatch')
class VirusTotalReportView(APIView):
    def get(self, request, *args, **kwargs):
        file_hash = request.GET.get("hash", "").strip()
        if not file_hash:
            return JsonResponse({"error": "Missing file hash"}, status=400)

        api_key = os.getenv("VIRUS_TOTAL")
        if not api_key:
            return JsonResponse({"error": "API key not configured"}, status=500)

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = httpx.get(url, headers={"x-apikey": api_key})
            if response.status_code == 200:
                return JsonResponse(response.json())
            return JsonResponse(
                {"error": "Analysis not available", "status": response.status_code},
                status=response.status_code
            )
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)