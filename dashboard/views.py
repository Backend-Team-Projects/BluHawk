import threading
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated

from django.core.mail import send_mail
from django.utils.timezone import now

from datetime import  timedelta

import traceback, json, re, requests, gc
from BluHawk.load_env import VIRUS_TOTAL

from dashboard.models import (
    CveNvd,
    MitreAttackEntity as mit_entity,
    MitreEntityRelation as relation,
    Subscribers,
    Misp,
    WapitiReports as wapiti_report,
    OpenPorts as open_ports,
    Subdomains as subdomains,
    FullSubdomains as fsd,
    CompanyProfile as company_profile_model,
)

import math

from django.conf import settings
from django.template.loader import render_to_string

import google.generativeai as genai

import os
from dotenv import load_dotenv
from django.db.models import Q


from dashboard.port_scanning import port_scanner as ps
from dashboard.subdomain_search import fetch_subdomains as sd, fetch_subdomains_full as full_sd
from BluHawk.wapiti_vul_scan import get_wapiti_report
import base64
from BluHawk.AsyncDataProcessing import AsyncDataProcessing
from BluHawk.utils import *
from BluHawk import load_env as myenv

from django.http import JsonResponse
from dashboard.models import CveNvd as CVE
from dashboard.exa_company_profile import *


class ScanReportAsync(AsyncDataProcessing):
    def __init__(self):
        super().__init__(wapiti_report, 'id', get_wapiti_report, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class PortScanAsync(AsyncDataProcessing):
    def __init__(self):
        super().__init__(open_ports, 'id', ps, 60)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                ports = self.model(id=query, ports=response.get('data'))
                ports.save()

        except Exception as e:
            log_exception(e)

class SubdomainSearchAsync(AsyncDataProcessing):
    def __init__(self):
        super().__init__(subdomains, 'id', sd, 60)

    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                subdomain_object = self.model(id=query, subdomains=response.get('data'))
                subdomain_object.save()
        
        except Exception as e:
            log_exception(e)

class FullSubdomainSearchAsync(AsyncDataProcessing):
    def __init__(self):
        super().__init__(fsd, 'id', full_sd, 180)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                subdomain = self.model(id=query, subdomains=response.get('data'))
                subdomain.save()
        
        except Exception as e:
            log_exception(e)

class CompanyProfileAsync(AsyncDataProcessing):
    def __init__(self):
        super().__init__(company_profile_model, 'domain', create_company_profile, 360)
    
    def fetch_data(self, query, additional_data):
        # print(additional_data)
        
        if not query:
            return {'error': 'Query not provided'}

        filter_kwargs = {self.field: str(query).lower(), "company_name": str(additional_data['company_name']).lower()}
        results = self.model.objects.filter(**filter_kwargs)

        return results
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query, company_name = additional_data.get('company_name', ''))
            if response.get("status") == "success":
                profile = self.model(domain=str(query).lower(), json_data=response.get('data'), company_name = str(additional_data.get('company_name', '')).lower())
                profile.save()
        
        except Exception as e:
            log_exception(e)

company_profile = CompanyProfileAsync()
scan_rep = ScanReportAsync()
port_scan = PortScanAsync()
subdomain_search = SubdomainSearchAsync()
full_subdomain_search = FullSubdomainSearchAsync()

from datetime import datetime, timedelta, timezone

def check_data_freshness(data_object, days =1):
    try:
        now_utc = datetime.now(timezone.utc)
        
        updated_at = (
            data_object.get('updated_at')
            if isinstance(data_object, dict)
            else getattr(data_object, 'updated_at', None)
        )
        
        if isinstance(updated_at, datetime) and updated_at.tzinfo is not None:
            time_difference = now_utc - updated_at
            if timedelta(seconds=0) <= time_difference <= timedelta(days=days):
                return True

        return False
    except Exception as e:
        log_exception(e)
        return False

load_dotenv()
GEMINI_API = os.getenv("GEMINI_API_KEY")

class MyIntel(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            query = request.query_params.get("query", "").strip().lower()
            type_filter = request.query_params.get("type_filter", None)
            id = request.query_params.get("id", None)
            page = int(request.query_params.get("page", 1)) - 1
            page_size = int(request.query_params.get("page_size", 50))
            self.reduced = request.query_params.get("reduced", True)
            source = request.query_params.get("source", None)

            if id:
                self.reduced = False

            if (not query) and not id:
                return Response({"message": "No query provided!"}, status=status.HTTP_400_BAD_REQUEST)
            
            if page_size >50 or page_size < 10:
                page_size = 50

            offset = max(0, page * page_size)
            limit = page_size

            data, single_object, total_count = self.search_intel(query, type_filter, id, source, offset, limit)

            if single_object:
                # print("single object", data)
                return Response({"data": data if isinstance(data, dict) else data[0]}, status=status.HTTP_200_OK)
            
            return Response({
                "data": data,
                "current_page": page + 1,
                "total_pages": math.ceil(total_count / page_size)
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return log_exception(e)

    def search_intel(self, query, type_filter, id, source, offset, limit):
        try:
            if source == "Mitre":
                intel_data = mit_entity.objects.filter(id=id) if id else mit_entity.objects.filter(name__istartswith=query)

                try:
                    intel_data = intel_data.filter(json_data__x_mitre_deprecated=False)
                except Exception as e:
                    log_exception(e)

                if type_filter and not id:
                    intel_data = intel_data.filter(type=type_filter)

                total_count = intel_data.count()
                if not id:
                    intel_data = intel_data.order_by("id").distinct()[offset:offset + limit]

                intel_data_list = list(intel_data.values())

                for item in intel_data_list:
                    item["source_type"] = "mitre"
                    rel = relation.objects.filter(source_ref=item["id"])

                    if not self.reduced:
                        try:
                            rel = rel.filter(json_data__revoked=False, json_data__x_mitre_deprecated=False)
                        except Exception as e:
                            log_exception(e)

                        relations_list = list(rel.values().distinct())

                        if id:
                            for rel in relations_list:
                                try:
                                    rel["target_mitre_id"] = mit_entity.objects.filter(id=rel["target_ref"]).first().mitre_object_id
                                except Exception as e:
                                    log_exception(e)

                        item["relation"] = relations_list

                if id:
                    return intel_data_list[0] if intel_data_list else {}, True, total_count
                return intel_data_list, False, total_count

            elif source == "MISP":
                misp_data, total = self.search_intel_misp(query, id, type_filter, offset, limit)
                return misp_data if not id else (misp_data[0] if misp_data else {}), bool(id), total

            elif source == "CVE":
                cve_data, total = self.search_intel_cve(query, id, type_filter, limit, offset)
                # print("Total: ",total, cve_data, cve_data if not id else (cve_data[0] if cve_data else {}))
                return cve_data if not id else (cve_data[0] if cve_data else {}), bool(id), total

            else:
                return [], False, 0

        except Exception as e:
            log_exception(e)
            return [], False, 0

    def search_intel_cve(self, query, id=None, type_filter=None, limit=50, offset=0):
        try:
            if id:
                from dashboard.models import CPE as cpe
                from django.db.models import Prefetch

                intel_data = CVE.objects.filter(id=id).prefetch_related(
                        Prefetch('cpe_entries', queryset=cpe.objects.only('id', 'json_data'))
                    )
                
                # print("first case: ", intel_data)
            else:
                intel_data = CVE.objects.filter(Q(name__icontains=query) | Q(id__icontains=query))

            if type_filter and not id:
                intel_data = intel_data.filter(type=type_filter)

            total_count = intel_data.count()
            if not id:
                intel_data = intel_data.order_by('id').distinct()[offset:offset + limit]
            
            if id:
                intel_data_list = list(intel_data.values('id', 'type', 'name', 'json_data', "cpe_entries"))
                
            else:
                intel_data_list = list(intel_data.values('id', 'type', 'name', 'json_data'))
            
            for item in intel_data_list:
                item["source_type"] = "CVE"
            
            return intel_data_list, total_count

        except Exception as e:
            log_exception(e)
            return [], 0

    def search_intel_misp(self, query, id=None, type_filter=None, offset=0, limit=50):
        try:
            intel_data = Misp.objects.filter(id=id) if id else Misp.objects.filter(name__istartswith=query)

            if type_filter and not id:
                intel_data = intel_data.filter(type=type_filter)

            total_count = intel_data.count()
            if not id:
                intel_data = intel_data.order_by('id').distinct()[offset:offset + limit]
            intel_data_list = list(intel_data.values('id', 'type', 'name', 'json_data'))

            for item in intel_data_list:
                item["source_type"] = "MISP"

            return intel_data_list, total_count

        except Exception as e:
            log_exception(e)
            return [], 0


# class FindIntel(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request, *args, **kwargs):
#         try:
#             query = request.query_params.get("query", None)
#             search_type = request.query_params.get(
#                 "search_type", None
#             )
#             if (
#                 not query
#                 or not search_type
#                 or search_type not in ["ip", "domain", "hash", "url"]
#             ):
#                 return Response(
#                     {"message": "invalid query or search type!"},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
            
#             if search_type == "url":
#                 return self.url_scan(query)

#             data = {}
#             data["virus_total"] = self.vt_search(query, search_type)
            
#             return Response(data, status=status.HTTP_200_OK)

#         except Exception as e:
#             return log_exception(e)

#     def vt_search(self, query, search_type):
#         base_url = "https://www.virustotal.com/api/v3"

#         endpoints = {
#             "ip": f"{base_url}/ip_addresses/{query}",
#             "domain": f"{base_url}/domains/{query}",
#             "hash": f"{base_url}/files/{query}",
#         }

#         url = endpoints.get(search_type)
#         if not url:
#             return {"error": "Invalid search type"}

#         headers = {"accept": "application/json", "x-apikey": VIRUS_TOTAL}

#         response = requests.get(url, headers=headers)
#         return response.json()
    
#     def url_scan(self, query):
#         encoded_url = self.encode_url_base64(query)
#         url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
#         headers = {
#             "accept": "application/json",
#             "x-apikey": VIRUS_TOTAL
#         }

#         response = requests.get(url, headers=headers)

#         if response.status_code == 404:
#             submit_scan_url = "https://www.virustotal.com/api/v3/urls"
#             scan_headers = {
#                 "accept": "application/json",
#                 "content-type": "application/x-www-form-urlencoded",
#                 "x-apikey": "VIRUS_TOTAL"
#             }
#             data = {"url": query}

#             scan_response = requests.post(submit_scan_url, headers=scan_headers, data=data)


#             if scan_response.status_code == 200:
#                 response = requests.get(url, headers=headers)
#                 return Response({"virus_total":response.json()}, status=status.HTTP_200_OK)

#             else:
#                 return Response(scan_response.json(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         else: 
#             if response.status_code == 200:
#                 return Response({"virus_total": response.json()}, status=status.HTTP_200_OK)
#             elif response.status_code == 400:
#                 return Response(
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
#             else:
#                 return Response(
#                     status=500,
#                 )
    
#     def encode_url_base64(self, url):
#         url_bytes = url.encode("utf-8")
#         base64_bytes = base64.urlsafe_b64encode(url_bytes)
#         return base64_bytes.decode("utf-8").rstrip("=")

class Subscribe(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            entity_id = request.query_params.get("entity_id", None)
            entity_source = request.query_params.get("entity_source", None)
            if not user or not entity_id or not entity_source:
                return Response(
                    {"message": "Invalid data provided!", "subscribed": 0},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if entity_source == "mitre":
                object = mit_entity.objects.filter(id=entity_id).first()
            else:
                pass
                # object = cisa_vul.objects.filter(id=entity_id).first()

            if Subscribers.objects.filter(email=user.email, entity_id=object).exists():
                return Response(
                    {"message": "Already subscribed!", "subscribed": 1},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "Not subscribed!", "subscribed": 0},
                    status=status.HTTP_200_OK,
                )

        except Exception as e:
            return log_exception(e)

    def post(self, request, *args, **kwargs):
        try:
            user = request.user
            entity_id = request.data.get("entity_id", None)
            entity_source = request.data.get("entity_source", None)
            if not user or not entity_id or not entity_source:
                return Response(
                    {"message": "Invalid data provided!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if entity_source == "mitre":
                object = mit_entity.objects.filter(id=entity_id).first()
            else:
                pass
                # object = cisa_vul.objects.filter(id=entity_id).first()

            if Subscribers.objects.filter(email=user.email, entity_id=object).exists():
                return Response(
                    {"message": "Already subscribed!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            else:
                data = self.subscribe(user.email, entity_id, entity_source)
                return data

        except Exception as e:
            return log_exception(e)

    def subscribe(self, email, entity_id, entity_source):
        try:
            if entity_source == "mitre":
                object = mit_entity.objects.filter(id=entity_id).first()
            else:
                pass
                # object = cisa_vul.objects.filter(id=entity_id).first()

            subscriber = Subscribers(
                email=email, entity_id=entity_id, entity_source=entity_source
            )
            subscriber.save()

            html_content = render_to_string(
                "successfully_subscribed.html",
                {
                    "subscription_name": object.name,
                },
            )

            send_mail(
                "Successfully Subscribed",
                f"Click the link below to reset your password:\n\nlslnjk",
                recipient_list=[email],
                from_email=myenv.ADMIN_EMAIL,
                auth_user=myenv.EMAIL_HOST_USER,
                auth_password=myenv.EMAIL_HOST_PASSWORD,
                fail_silently=True,
                html_message=html_content,
            )

            return Response(
                {"message": "Subscribed successfully!"}, status=status.HTTP_200_OK
            )

        except Exception as e:
            return log_exception(e)

class Unsubscribe(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            entity_id = request.query_params.get("entity_id", None)
            entity_source = request.query_params.get("entity_source", None)
            if not user or not entity_id or not entity_source:
                return Response(
                    {"message": "Invalid data provided!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if entity_source == "mitre":
                object = mit_entity.objects.filter(id=entity_id).first()
            else:
                pass
                # object = cisa_vul.objects.filter(id=entity_id).first()

            if Subscribers.objects.filter(email=user.email, entity_id=object).exists():
                data = self.unsubscribe(user.email, entity_id, entity_source)
                return data
            else:
                return Response(
                    {"message": "Not subscribed!"}, status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            return log_exception(e)

    def unsubscribe(self, email, entity_id, entity_source):
        try:
            if entity_source == "mitre":
                object = mit_entity.objects.filter(id=entity_id).first()
            else:
                pass
                # object = cisa_vul.objects.filter(id=entity_id).first()

            subscriber = Subscribers.objects.filter(
                email=email, entity_id=object
            ).first()
            subscriber.delete()

            html_content = render_to_string(
                "successfully_unsubscribed.html",
                {
                    "subscription_name": object.name,
                },
            )

            send_mail(
                "Successfully Unsubscribed",
                f"Click the link below to reset your password:\n\nlslnjk",
                recipient_list=[email],
                fail_silently=True,
                html_message=html_content,
                from_email=myenv.ADMIN_EMAIL,
                auth_user=myenv.EMAIL_HOST_USER,
                auth_password=myenv.EMAIL_HOST_PASSWORD,
            )

            return Response(
                {"message": "Unsubscribed successfully!"}, status=status.HTTP_200_OK
            )

        except Exception as e:
            return log_exception(e)

# class WapitiVulScanning(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request, *args, **kwargs):
#         try:
#             query = request.query_params.get("query", None)
#             if not query:
#                 return Response(
#                     {"message": "No query provided!"},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             data = scan_rep.handle(query=query)
#             if data.get("status") == "completed":
#                 if check_data_freshness(data.get('data', {})):
#                     return Response(data , status=status.HTTP_200_OK)
#                 else:
#                     wapiti_report.objects.filter(id=query).delete()
#                     data = scan_rep.handle(query=query)
#                     return Response(data, status=status.HTTP_202_ACCEPTED)
#             elif data.get("status", 'error') == "processing":
#                 return Response(data, status=status.HTTP_202_ACCEPTED)
#             else:
#                 return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#         except Exception as e:
#             return log_exception(e)

# class PortScanning(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request, *args, **kwargs):
#         try:
#             query = request.query_params.get("query", None)
#             if not query:
#                 return Response(
#                     {"message": "No query provided!"},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             data = port_scan.handle(query=query)
#             if data.get("status", 'error') == "completed":
#                 if check_data_freshness(data.get('data', {})):
#                     return Response(data , status=status.HTTP_200_OK)
#                 else:
#                     open_ports.objects.filter(id=query).delete()
#                     data = port_scan.handle(query=query)
#                     return Response(data, status=status.HTTP_202_ACCEPTED)
#             elif data.get("status", 'error') == "processing":
#                 return Response(data, status=status.HTTP_202_ACCEPTED)
#             else:
#                 return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#         except Exception as e:
#             return log_exception(e)

# class SubdomainSearch(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request, *args, **kwargs):
#         try:
#             query = request.query_params.get("query", None)
#             if not query:
#                 return Response(
#                     {"message": "No query provided!"},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             data = subdomain_search.handle(query=query)
#             if data.get("status", 'error') == "completed":
#                 if check_data_freshness(data.get('data', {})):
#                     return Response(data , status=status.HTTP_200_OK)
#                 else:
#                     subdomains.objects.filter(id=query).delete()
#                     data = subdomain_search.handle(query=query)
#                     return Response(data, status=status.HTTP_202_ACCEPTED)
#             elif data.get("status", 'error') == "processing":
#                 return Response(data, status=status.HTTP_202_ACCEPTED)
#             else:
#                 return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#         except Exception as e:
#             return log_exception(e)

# class FullSubdomainSearch(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request, *args, **kwargs):
#         try:
#             query = request.query_params.get("query", None)
#             if not query:
#                 return Response(
#                     {"message": "No query provided!"},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             data = full_subdomain_search.handle(query=query)
#             if data.get("status", 'error') == "completed":
#                 if check_data_freshness(data.get('data', {})):
#                     return Response(data , status=status.HTTP_200_OK)
#                 else:
#                     subdomains.objects.filter(id=query).delete()
#                     data = full_subdomain_search.handle(query=query)
#                     return Response(data, status=status.HTTP_200_OK)
#             elif data.get("status", 'error') == "processing":
#                 return Response(data, status=status.HTTP_202_ACCEPTED)
#             else:
#                 return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#         except Exception as e:
#             return log_exception(e)

class CompanyProfileSearch(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        try:
            query = request.query_params.get("query", None)
            company_name = request.query_params.get("company_name", None)
            if not query:
                return Response(
                    {"message": "No query provided!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            data = company_profile.handle(query=query.lower().strip(), additional_data={'company_name': str(company_name).lower().strip()})
            if data.get("status", 'error') == "completed":
                if check_data_freshness(data.get('data', {}), days = 15):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    company_profile_model.objects.filter(id=query).delete()
                    data = company_profile.handle(query=query, additional_data={'company_name': company_name})
                    return JsonResponse(data, status=status.HTTP_200_OK)
                
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            return log_exception(e)

from dashboard.tasks import *

class SearchVendorOrProduct(APIView):
    permission_classes = [IsAuthenticated]
    from dashboard.models import CPE as cpe

    def get(self, request, *args, **kwargs):
        query = request.query_params.get("query", None)
        search_type = request.query_params.get("search_type", None)
        id = request.query_params.get("id", None)

        if id:
            try:
                cpe_obj = self.cpe.objects.prefetch_related('cve_ids').filter(id=id).first()
                if cpe_obj:
                    result = {
                        "id": cpe_obj.id,
                        "vendor": cpe_obj.vendor,
                        "product": cpe_obj.product,
                        "cve_ids": list(cpe_obj.cve_ids.values_list("id", flat=True)),
                    }
                    from dashboard.models import CveNvd as CVE
                    cve_ids = CVE.objects.filter(id__in=result["cve_ids"]).values("id", "json_data")
                    return Response({"product": result, "cve": cve_ids}, status=status.HTTP_200_OK)

                else:
                    return Response({"message": "ID not found!"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return log_exception(e)

        page = int(request.query_params.get("page", 1)) - 1
        page_size = int(request.query_params.get("page_size", 50))

        if not query:
            return Response(
                {"message": "Invalid query!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            offset = page * page_size
            limit = page_size

            if search_type == "vendor":
                results = self.cpe.objects.filter(vendor__icontains=query).values(
                    "id", "vendor", "product", "name"
                )[offset:offset + limit]
                total_count = self.cpe.objects.filter(vendor__icontains=query).count()
            elif search_type == "product":
                results = self.cpe.objects.filter(product__icontains=query).values(
                    "id", "vendor", "product", "name"
                )[offset:offset + limit]
                total_count = self.cpe.objects.filter(product__icontains=query).count()
            else:
                results = self.cpe.objects.filter(
                    Q(vendor__icontains=query) | Q(product__icontains=query)
                ).values("id", "vendor", "product", "name")[offset:offset + limit]
                total_count = self.cpe.objects.filter(
                    Q(vendor__icontains=query) | Q(product__icontains=query)
                ).count()

            return Response(
                {
                    "data": list(results),
                    "current_page": page + 1,
                    "total_pages": math.ceil(total_count / page_size),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return log_exception(e)

class DBRefresh(APIView):
    def post(self, request, *args, **kwargs):
        try:
            SUPERUSER_PASSWORD = request.data.get("superuser_key", None)
            
            if not SUPERUSER_PASSWORD:
                return Response(
                    {"message": "No superuser key provided!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if SUPERUSER_PASSWORD != (myenv.SUPERUSER_PASSWORD):
                return Response(
                    {"message": "Invalid superuser key!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            threading.Thread(
                target=refresh_misp_data,
            ).start()

            threading.Thread(
                target=refreshMitreData,
            ).start()

            from dashboard.cve_data import download_and_process_cve_feeds as updateCVE

            threading.Thread(
                target=updateCVE,
            ).start()
            
            return Response({
                "message": "Refresh started!"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return log_exception(e)

def parse_datetime_safe(date_str):
    import datetime

    if date_str.endswith('Z'):
        date_str = date_str[:-1]
    try:
        return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")


def get_cve_data(cve_id):
    import datetime

    try:
        try:
            existing_cve = CveNvd.objects.get(id=cve_id)

            return {
                    "status": "success",
                    "message": f"CVE data fetched from database (cached).",
                    "data": {
                        "id": existing_cve.id,
                        "type": existing_cve.type,
                        "name": existing_cve.name,
                        "modified": existing_cve.modified,
                        "created": existing_cve.created,
                        "json_data": existing_cve.json_data
                    }
                }
            # now = datetime.datetime.now(datetime.timezone.utc)
            # time_diff = now - existing_cve.updated_at

            # if time_diff.days < 10:
                # return {
                #     "status": "success",
                #     "message": f"CVE data fetched from database (cached, last updated {time_diff.days} days ago).",
                #     "data": {
                #         "id": existing_cve.id,
                #         "type": existing_cve.type,
                #         "name": existing_cve.name,
                #         "modified": existing_cve.modified,
                #         "created": existing_cve.created,
                #         "json_data": existing_cve.json_data
                #     }
                # }
            # else:
            #     response = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
            #     if response.status_code != 200:
            #         return {
            #             "status": "error",
            #             "message": f"Failed to fetch CVE data. Status code: {response.status_code}"
            #         }

            #     api_data = response.json()
            #     metadata = api_data.get("cveMetadata", {})
            #     cna_data = api_data.get("containers", {}).get("cna", {})

            #     CveNvd.objects.update_or_create(
            #         id=metadata.get("cveId"),
            #         defaults={
            #             "type": metadata.get("state", "Unknown"),
            #             "name": cna_data.get("title", "No Title"),
            #             "modified": parse_datetime_safe(metadata.get("dateUpdated")),
            #             "created": parse_datetime_safe(metadata.get("datePublished")),
            #             "json_data": api_data
            #         }
            #     )

            #     return {
            #         "status": "success",
            #         "message": "CVE data updated from API (was older than 10 days).",
            #         "data": api_data
            #     }

        except CveNvd.DoesNotExist:
            response = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
            if response.status_code != 200:
                return {
                    "status": "error",
                    "message": f"Failed to fetch CVE data. Status code: {response.status_code}"
                }

            data = response.json()
            metadata = data.get("cveMetadata", {})
            cna_data = data.get("containers", {}).get("cna", {})

            CveNvd.objects.create(
                id=metadata.get("cveId"),
                type=metadata.get("state", "Unknown"),
                name=cna_data.get("title", "No Title"),
                modified=parse_datetime_safe(metadata.get("dateUpdated")),
                created=parse_datetime_safe(metadata.get("datePublished")),
                json_data=data
            )

            return {
                "status": "success",
                "message": "CVE data fetched from API and saved to DB.",
                "data": data
            }

    except Exception as e:
        log_exception(e)
        return {
            "status": "error",
            "message": f"Something went wrong: {str(e)}"
        }

class FetchAndCreateCVEView(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self, request, cve_id):
        result = get_cve_data(cve_id)
        return JsonResponse(result, status=500 if result.get("status") == "error" and "Something went wrong" in result.get("message") else 200)



from django.utils.timezone import now
from datetime import timedelta
from dashboard.models import FullScanReport
from dashboard.subdomain_search import fetch_rapiddns
import threading, base64, requests, json, socket, subprocess, os
from BluHawk.config import COMMON_TCP_PORTS
from urllib.parse import urlparse
from django.conf import settings
from django.db import transaction
from functools import partial
import ipaddress
import time
import sys

logger = logging.getLogger(__name__)

VIRUS_TOTAL_API_KEY = os.environ.get("VIRUS_TOTAL")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
SCAN_TIMEOUT = timedelta(minutes=10)

# Status codes
STATUS_COMPLETED = 200
STATUS_PROCESSING = 202
STATUS_PARTIAL = 206
STATUS_BAD_REQUEST = 400
STATUS_FORBIDDEN = 403
STATUS_NOT_FOUND = 404
STATUS_TIMEOUT = 408
STATUS_SERVICE_UNAVAILABLE = 503

class FindIntelFullScan(APIView):
    permission_classes = [IsAuthenticated]
    FORCE_RESCAN_CODES = [STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_TIMEOUT, STATUS_SERVICE_UNAVAILABLE]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Debug logging to verify method availability
        logger.debug("Available methods in FindIntelFullScan: %s", [method for method in dir(self) if callable(getattr(self, method))])

    def get(self, request):
        try:
            query = request.query_params.get("query")
            search_type = request.query_params.get("search_type")

            if not query or search_type not in ["ip", "domain", "hash", "url"]:
                return Response({"message": "Invalid query or search_type"}, status=400)

            query = query.strip().lower()
            required_scans = self.get_required_scans(search_type)

            try:
                report = FullScanReport.objects.get(id=query)
                data = report.scan_data or {}
                scan_age = now() - report.scan_started_at

                # ---------------------- 24-Hour Check ----------------------
                if scan_age.total_seconds() > 24 * 3600:
                    # Reset old scan for a new run instead of deleting
                    with transaction.atomic():
                        report.scan_started_at = now()
                        report.scan_completed_at = None
                        report.status = STATUS_PROCESSING
                        report.scan_data = {}  # clear previous scan data
                        report.save()
                    self.start_all_scans(query, search_type)
                    return Response({
                        "status": "processing",
                        "message": "Previous scan older than 24h. New scan started.",
                        "scan_started_at": report.scan_started_at
                    }, status=STATUS_PROCESSING)

                 # Retry if previous scan was partial
                if report.status == STATUS_PARTIAL:
                    report.status = STATUS_PROCESSING
                    report.scan_started_at = now()
                    scans_to_run = self.get_scans_to_retry(data, required_scans, search_type, query)
                    if scans_to_run:
                        self.run_scan_threads(scans_to_run, query, search_type)
                        with transaction.atomic():
                            report.save()
                        return Response({
                            "status": "processing",
                            "message": "Retrying failed scans from previous partial",
                            "scan_started_at": report.scan_started_at
                        }, status=STATUS_PROCESSING)

                # Timeout handling
                if report.status != STATUS_COMPLETED and scan_age > SCAN_TIMEOUT:
                    for scan_type in required_scans:
                        status_code = data.get(scan_type, {}).get("status_code", STATUS_TIMEOUT)
                        if status_code in [STATUS_PROCESSING, STATUS_TIMEOUT]:
                            data[scan_type] = {
                                "status_code": STATUS_TIMEOUT,
                                "result": {},
                                "last_updated": now().isoformat(),
                                "fatal": False
                            }
                    report.status = STATUS_PARTIAL
                    report.scan_data = data
                    with transaction.atomic():
                        report.save()
                    return Response({
                        "status": "partial",
                        "message": "Scan exceeded timeout. Incomplete scans marked as timeout.",
                        "scan_started_at": report.scan_started_at,
                        "data": data
                    }, status=STATUS_PARTIAL)

                scans_to_run = self.get_scans_to_retry(data, required_scans, search_type, query)
                statuses = self.check_scan_statuses(data, required_scans)

                # If overall scan is completed but individual scan failed, retry only the failed ones
                if report.status == STATUS_COMPLETED and any(s in self.FORCE_RESCAN_CODES for s in statuses):
                    report.status = STATUS_PROCESSING
                    report.scan_started_at = now()
                    with transaction.atomic():
                        report.save()
                    if scans_to_run:
                        self.run_scan_threads(scans_to_run, query, search_type)
                        return Response({
                            "status": "processing",
                            "scan_sign": "retry_due_to_partial_failure",
                            "scan_started_at": report.scan_started_at,
                            "data": data
                        }, status=STATUS_PROCESSING)

                # If all scans are either successful or unrecoverable (non-retryable), mark as completed
                if all(s in [STATUS_COMPLETED, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
                            STATUS_NOT_FOUND, STATUS_SERVICE_UNAVAILABLE] for s in statuses):
                    report.status = STATUS_COMPLETED
                    report.scan_completed_at = now()
                    with transaction.atomic():
                        report.save()
                    return Response({
                        "status": "completed",
                        "scan_started_at": report.scan_started_at,
                        "scan_completed_at": report.scan_completed_at,
                        "data": data
                    }, status=STATUS_COMPLETED)

                # Retry any remaining scans
                if scans_to_run:
                    report.status = STATUS_PROCESSING
                    report.scan_data = data
                    with transaction.atomic():
                        report.save()
                    self.run_scan_threads(scans_to_run, query, search_type)
                    return Response({
                        "status": "processing",
                        "scan_sign": "pending_scans",
                        "scan_started_at": report.scan_started_at,
                        "data": data
                    }, status=STATUS_PROCESSING)

                # No scans to run; still waiting
                return Response({
                    "status": "processing",
                    "scan_sign": "waiting_scans",
                    "scan_started_at": report.scan_started_at,
                    "data": data
                }, status=STATUS_PROCESSING)

            except FullScanReport.DoesNotExist:
                with transaction.atomic():
                    FullScanReport.objects.create(
                        id=query,
                        search_type=search_type,
                        scan_started_at=now(),
                        status=STATUS_PROCESSING
                    )
                self.start_all_scans(query, search_type)
                return Response({
                    "status": "processing",
                    "message": "Scan started. Use same endpoint to poll results."
                }, status=STATUS_PROCESSING)

        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=500)


    def get_required_scans(self, search_type):
        return {
            "domain": ["virus_total", "wapiti_report", "open_ports", "subdomains"],
            "url": ["virus_total", "wapiti_report", "open_ports", "subdomains"],
            "ip": ["virus_total", "wapiti_report", "open_ports"],
            "hash": ["virus_total"]
        }.get(search_type, [])

    def check_scan_statuses(self, data, required_scans):
        return [data.get(key, {}).get("status_code", STATUS_BAD_REQUEST) for key in required_scans]

    def get_scans_to_retry(self, data, required_scans, search_type, query):
        logger.debug("Entering get_scans_to_retry for query: %s, search_type: %s", query, search_type)
        scan_map = {
            "virus_total": (partial(self.vt_scan, query, search_type), "virus_total"),
            "wapiti_report": (partial(self.wapiti_scan, query, search_type), "wapiti_report"),
            "open_ports": (partial(self.port_scan, query, search_type), "open_ports"),
            "subdomains": (partial(self.subdomain_scan, query, search_type), "subdomains")
        }
        scans_to_run = []
        data = data or {}
        for scan_type in required_scans:
            scan_data = data.get(scan_type, {})
            status_code = scan_data.get("status_code")
            if status_code in self.FORCE_RESCAN_CODES or status_code is None:
                data[scan_type] = {
                    "status_code": STATUS_PROCESSING,
                    "result": {},
                    "last_updated": now().isoformat(),
                    "fatal": False
                }
                scans_to_run.append(scan_map[scan_type])
        logger.debug("Scans to retry: %s", [scan_type for _, scan_type in scans_to_run])
        return scans_to_run

    def start_all_scans(self, query, search_type):
        logger.debug("Entering start_all_scans for query: %s, search_type: %s", query, search_type)
        try:
            required_scans = self.get_required_scans(search_type)
            scan_map = {
                "virus_total": (partial(self.vt_scan, query, search_type), "virus_total"),
                "wapiti_report": (partial(self.wapiti_scan, query, search_type), "wapiti_report"),
                "open_ports": (partial(self.port_scan, query, search_type), "open_ports"),
                "subdomains": (partial(self.subdomain_scan, query, search_type), "subdomains")
            }
            scan_functions = [scan_map[stype] for stype in required_scans if stype in scan_map]
            self.run_scan_threads(scan_functions, query, search_type)
        except Exception as e:
            logger.error("Error in start_all_scans for query %s: %s", query, str(e))
            log_exception(e)

    def run_scan_threads(self, scan_functions, query, search_type):
        threads = []
        for fn, scan_type in scan_functions:
            try:
                print(f"[INFO] Starting thread for scan: {scan_type} | Query: {query}")
                thread = threading.Thread(target=fn, daemon=True)
                threads.append((thread, scan_type))
                thread.start()
            except Exception as e:
                logger.error(f"Failed to start thread for scan {scan_type} for query {query}: {str(e)}")
                log_exception(e)
                self.save_partial_result(query, {}, scan_type, STATUS_BAD_REQUEST, search_type)

        for thread, scan_type in threads:
            thread.join(timeout=600)  # Increased to match SCAN_TIMEOUT
            if thread.is_alive():
                print(f"[WARN] Thread for scan {scan_type} timed out for query {query}")
                logger.warning(f"Thread for scan {scan_type} timed out for query {query}")
                self.save_partial_result(query, {}, scan_type, STATUS_TIMEOUT, search_type)
            else:
                print(f"[INFO] Thread for scan {scan_type} completed for query {query}")

    def save_partial_result(self, query, result, scan_type, status_code, search_type):
        try:
            with transaction.atomic():
                scan_obj = FullScanReport.objects.select_for_update().get(id=query)
                scan_data = scan_obj.scan_data or {}

                fatal = result.get("fatal", False)
                scan_data[scan_type] = {
                    "status_code": status_code,
                    "result": result if status_code == STATUS_COMPLETED else {},
                    "last_updated": now().isoformat(),
                    "fatal": fatal
                }

                scan_obj.scan_data = scan_data
                required_scans = self.get_required_scans(search_type)
                statuses = self.check_scan_statuses(scan_data, required_scans)

                if all(s in [STATUS_COMPLETED, STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_SERVICE_UNAVAILABLE] for s in statuses):
                    scan_obj.status = STATUS_COMPLETED
                    scan_obj.scan_completed_at = now()
                elif any(s in self.FORCE_RESCAN_CODES for s in statuses):
                    scan_obj.status = STATUS_PARTIAL
                else:
                    scan_obj.status = STATUS_PROCESSING

                scan_obj.save()
        except Exception as e:
            logger.error(f"Failed to save partial result for {scan_type} on query {query}: {str(e)}")
            log_exception(e)

    def vt_scan(self, query, search_type):
        try:
            if not VIRUS_TOTAL_API_KEY or len(VIRUS_TOTAL_API_KEY.strip()) == 0:
                logger.error(f"VirusTotal API key missing or invalid for query {query}")
                self.save_partial_result(query, {}, "virus_total", STATUS_BAD_REQUEST, search_type)
                return

            headers = {
                "accept": "application/json",
                "x-apikey": VIRUS_TOTAL_API_KEY
            }
            base_url = "https://www.virustotal.com/api/v3"
            if search_type == "url":
                encoded = base64.urlsafe_b64encode(query.encode()).decode().rstrip("=")
                url = f"{base_url}/urls/{encoded}"
                resp = requests.get(url, headers=headers, timeout=30)
            else:
                endpoint = {
                    "ip": f"{base_url}/ip_addresses/{query}",
                    "domain": f"{base_url}/domains/{query}",
                    "hash": f"{base_url}/files/{query}"
                }.get(search_type)
                resp = requests.get(endpoint, headers=headers, timeout=30)

            if resp.status_code == STATUS_COMPLETED:
                self.save_partial_result(query, resp.json(), "virus_total", STATUS_COMPLETED, search_type)
            else:
                self.save_partial_result(query, {}, "virus_total", resp.status_code, search_type)
        except requests.Timeout:
            logger.error(f"VirusTotal scan timed out for query {query}")
            self.save_partial_result(query, {}, "virus_total", STATUS_TIMEOUT, search_type)
        except requests.RequestException as e:
            logger.error(f"VirusTotal scan failed for query {query}: {str(e)}")
            self.save_partial_result(query, {}, "virus_total", STATUS_BAD_REQUEST, search_type)
            log_exception(e)

    def wapiti_scan(self, query, search_type):
        try:
            original_query = query.strip().lower()
            self.save_partial_result(original_query, {"status": "running"}, "wapiti_report", STATUS_PROCESSING, search_type)

            if not query.startswith("http://") and not query.startswith("https://"):
                query = "http://" + query

            args = ["wapiti", "-u", query, "-f", "json", "-o", "/dev/stdout", "--scope", "page", "--max-links", "100"]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=600)

            if proc.returncode != 0:
                logger.error(f"Wapiti scan failed for query {query}: return code {proc.returncode}")
                self.save_partial_result(original_query, {}, "wapiti_report", STATUS_BAD_REQUEST, search_type)
                return

            data = json.loads(proc.stdout[proc.stdout.index('{'):proc.stdout.rindex('}') + 1])
            parsed = urlparse(query)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            host_type = "IP" if self._is_ip(parsed.hostname) else "Domain"

            result = {
                "vulnerabilities": data.get("vulnerabilities", {}),
                "target_info": {
                    "normalized_url": query,
                    "host_type": host_type,
                    "port": port,
                    "scheme": parsed.scheme
                },
                "stats": data.get("scan", {})
            }
            self.save_partial_result(original_query, result, "wapiti_report", STATUS_COMPLETED, search_type)
        except subprocess.TimeoutExpired:
            logger.error(f"Wapiti scan timed out for query {query}")
            self.save_partial_result(original_query, {}, "wapiti_report", STATUS_TIMEOUT, search_type)
        except Exception as e:
            logger.error(f"Wapiti scan failed for query {query}: {str(e)}")
            self.save_partial_result(original_query, {}, "wapiti_report", STATUS_BAD_REQUEST, search_type)
            log_exception(e)

    def port_scan(self, query, search_type):
        if search_type == "hash":
            return
        try:
            parsed = urlparse(query)
            hostname = parsed.hostname or query
            ip = socket.gethostbyname(hostname)
            self.save_partial_result(query, {"status": "processing"}, "open_ports", STATUS_PROCESSING, search_type)

            if SHODAN_API_KEY:
                try:
                    import shodan
                    api = shodan.Shodan(SHODAN_API_KEY)
                    host = api.host(ip)
                    ports = host.get("ports", [])
                    self.save_partial_result(query, {"ports": ports}, "open_ports", STATUS_COMPLETED, search_type)
                    return
                except Exception as shodan_error:
                    logger.warning(f"Shodan scan failed for {ip}: {shodan_error}. Falling back to socket scan.")

            open_ports = []
            lock = threading.Lock()

            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        if s.connect_ex((ip, port)) == 0:
                            with lock:
                                open_ports.append(port)
                except socket.timeout:
                    pass
                except Exception as e:
                    logger.debug(f"Port scan failed for port {port} on {ip}: {str(e)}")
                    log_exception(e)

            threads = []
            for port in COMMON_TCP_PORTS:
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            open_ports.sort()
            self.save_partial_result(query, {"ports": open_ports}, "open_ports", STATUS_COMPLETED, search_type)

        except socket.gaierror:
            logger.error(f"Failed to resolve hostname {hostname} for query {query}")
            self.save_partial_result(query, {}, "open_ports", STATUS_BAD_REQUEST, search_type)
        except Exception as e:
            logger.error(f"Port scan failed for query {query}: {str(e)}")
            self.save_partial_result(query, {}, "open_ports", STATUS_BAD_REQUEST, search_type)
            log_exception(e)

    def subdomain_scan(self, query, search_type):
        if search_type in ["hash", "ip"]:
            print(f"[SKIP] Subdomain scan skipped for type: {search_type}")
            return
        try:
            print(f"[START] Subdomain scan started for query: {query}")
            self.save_partial_result(query, {"status": "processing"}, "subdomains", STATUS_PROCESSING, search_type)
            parsed = urlparse(query)
            domain = parsed.hostname or query
            data = fetch_rapiddns(domain)
            if data.get("status") == "success":
                subdomains = data.get("data", [])
                print(f"[SUCCESS] Subdomain scan completed with {len(subdomains)} subdomains for query: {query}")
                self.save_partial_result(query, {"subdomains": list(subdomains)}, "subdomains", STATUS_COMPLETED, search_type)
            else:
                print(f"[ERROR] Subdomain scan failed (API error) for query: {query}")
                logger.error(f"Subdomain scan failed for query {query}: {data.get('message', 'Unknown error')}")
                self.save_partial_result(query, {}, "subdomains", STATUS_BAD_REQUEST, search_type)
        except Exception as e:
            print(f"[EXCEPTION] Subdomain scan crashed for query: {query}")
            logger.error(f"Subdomain scan failed for query {query}: {str(e)}")
            self.save_partial_result(query, {}, "subdomains", STATUS_BAD_REQUEST, search_type)
            log_exception(e)

    def _is_ip(self, value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False