import requests
import urllib.parse
from django.http import JsonResponse
from django.views import View
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/graphs"

ALLOWED_FILTER_TYPES = ["domain", "ip_address", "file", "url", "label"]

# class FilterTypeView(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request):
#         filter_type = request.query_params.get("filter_type", "domain").lower()
#         query = request.query_params.get("query")

#         if not query:
#             return Response(
#                 {"error": "Missing 'query' parameter."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         if filter_type not in ALLOWED_FILTER_TYPES:
#             return Response(
#                 {
#                     "error": "Invalid filter type.",
#                     "allowed_types": ALLOWED_FILTER_TYPES,
#                     "default": "domain"
#                 },
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         # Construct filter string (e.g., domain:google)
#         filter_string = f"{filter_type}:{query}"

#         # Encode URL parameters
#         params = {"filter": filter_string}
#         full_url = f"{VIRUSTOTAL_API_URL}?{urllib.parse.urlencode(params)}"


#         return Response(
#             {
#                 "encoded_url": full_url
#             },            status=status.HTTP_200_OK
#         )


class VirusTotalGraphSearchView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self, request):
        filter_type = request.query_params.get("filter_type", "domain").lower()
        query = request.query_params.get("query", "").lower()

        if not query:
            return Response(
                {"error": "Missing 'query' parameter."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if filter_type not in ALLOWED_FILTER_TYPES:
            return Response(
                {
                    "error": "Invalid filter type.",
                    "allowed_types": ALLOWED_FILTER_TYPES,
                    "default": "domain"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Construct filter string (e.g., domain:google)
        filter_string = f"{filter_type}:{query}"

        params = {
            "limit": request.GET.get("limit", 15),
            "cursor": request.GET.get("cursor"),
            "order": request.GET.get("order"),
            "attributes": request.GET.get("attributes"),
        }

        params = {k: v for k, v in params.items() if v is not None}

        params['filter'] = filter_string

        print(params)

        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY,
        }

        try:
            vt_response = requests.get(
                VIRUSTOTAL_API_URL,
                headers=headers,
                params=params  
            )

            # print(vt_response.json())
            return JsonResponse(vt_response.json(), status=vt_response.status_code)
        except requests.RequestException as e:
            return JsonResponse({"error": str(e)}, status=500)


