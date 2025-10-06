from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
import httpx
import os
import hashlib

class VirusTotalReportView(APIView):
    parser_classes = (MultiPartParser, FormParser)  # For file uploads

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

    def post(self, request, *args, **kwargs):
        try:
            # Check if file is provided
            if 'file' not in request.FILES:
                return JsonResponse({"error": "No file provided"}, status=400)

            file_obj = request.FILES['file']
            api_key = os.getenv("VIRUS_TOTAL")
            if not api_key:
                return JsonResponse({"error": "API key not configured"}, status=500)

            # Calculate SHA256 hash
            sha256_hash = hashlib.sha256()
            for chunk in file_obj.chunks():
                sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()

            # Reset file pointer to start for upload
            file_obj.seek(0)

            # Submit file to VirusTotal
            url = "https://www.virustotal.com/api/v3/files"
            files = {"file": (file_obj.name, file_obj, file_obj.content_type)}
            headers = {"x-apikey": api_key}
            response = httpx.post(url, headers=headers, files=files)

            if response.status_code == 200:
                response_data = response.json()
                analysis_id = response_data.get("data", {}).get("id")

                # Fetch analysis report using the hash
                report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                report_response = httpx.get(report_url, headers={"x-apikey": api_key})
                report_data = report_response.json() if report_response.status_code == 200 else {"error": "Report not available", "status": report_response.status_code}

                return JsonResponse({
                    "message": "File submitted successfully",
                    "sha256": file_hash,
                    "analysis_id": analysis_id,
                    "file_name": file_obj.name,
                    "report": report_data
                }, status=200)
            return JsonResponse(
                {"error": "Failed to submit file", "status": response.status_code},
                status=response.status_code
            )

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)