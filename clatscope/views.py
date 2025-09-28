from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers

from django.utils.timezone import now

from datetime import  timedelta

import traceback, json, re, requests, gc
from BluHawk.load_env import VIRUS_TOTAL


from django.conf import settings
from django.template.loader import render_to_string


import os
from dotenv import load_dotenv
from BluHawk.AsyncDataProcessing import AsyncDataProcessing
from BluHawk.utils import *
from clatscope.models import *
    
from clatscope.ClatScope import (
    ip_info,
    deep_account_search,
    phone_info,
    check_ssl_cert,
    wayback_lookup,
    username_check,
    whois_lookup,
    check_data_freshness
)

from datetime import datetime, timedelta, timezone
import subprocess
from dashboard.views import get_cve_data
import time

# def get_nrich_data(ip_address):
#     result = subprocess.run(
#             ["nrich", "-o", "json", "-"],
#             input=ip_address,
#             text=True,
#             capture_output=True,
#             check=True
#         )
    
            
#     data = json.loads(result.stdout)[0]
#     try:
#         cve_data_list = {}
#         vulns = data.get('vulns')
#         for vuln in vulns:
#                 print(vuln)
#                 cve_id = vuln
#                 cve_data = get_cve_data(cve_id)
#                 if cve_data.get('status', 'error') == 'success':
#                     cve_data_list[cve_id] = get_cve_data(cve_id).get('data', {}).get('json_data', {})

#         data['cve_vulns'] = cve_data_list

#     except Exception as e:
#         log_exception(e)

#     return {
#             "status": "success",
#             "data": [data]
#         }

def get_nrich_data(ip_address):
    result = subprocess.run(
        ["nrich", "-o", "json", "-"],
        input=ip_address,
        text=True,
        capture_output=True,
        check=True
    )
    
    try:
        data_list = json.loads(result.stdout)
        if not data_list:
            return {"status": "error", "message": "No data returned for this IP", "data": []}
        
        data = data_list[0]
        
        cve_data_list = {}
        vulns = data.get('vulns', [])
        for vuln in vulns:
            cve_data = get_cve_data(vuln)
            if cve_data.get('status') == 'success':
                cve_data_list[vuln] = cve_data.get('data', {}).get('json_data', {})
        data['cve_vulns'] = cve_data_list

        return {"status": "success", "data": [data]}
    
    except Exception as e:
        log_exception(e)
        return {"status": "error", "message": str(e), "data": []}



def check_data_freshness(data_object):
        now_utc = datetime.now(timezone.utc)
        
        updated_at = (
            data_object.get('updated_at')
            if isinstance(data_object, dict)
            else getattr(data_object, 'updated_at', None)
        )
        
        if isinstance(updated_at, datetime) and updated_at.tzinfo is not None:
            time_difference = now_utc - updated_at
            if timedelta(seconds=0) <= time_difference <= timedelta(days=7):
                return True
        return False

class deep_account_search_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(DeepAccountSearch, 'id', deep_account_search, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class ip_info_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(IPInfo, 'id', ip_info, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class PhoneNumberInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneNumberInfo
        fields = ['id', 'json_data', 'created', 'updated_at']

def clean_phone_number(phone_number):
    # Remove <, >, spaces, etc., but keep the leading +
    phone_number = phone_number.strip()
    phone_number = phone_number.replace('<', '').replace('>', '').replace(' ', '')
    
    if phone_number.startswith('+'):
        return '+' + re.sub(r'[^\d]', '', phone_number)
    else:
        return re.sub(r'[^\d]', '', phone_number)

class phone_info_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(PhoneNumberInfo, 'id', phone_info, 600)
    
    def save_data(self, query, additional_data):
        # print(f"[DEBUG] save_data started for query: {query}")
        try:
            response = self.fun(query) or {}
            # print(f"[DEBUG] phone_info response: {response}")
            
            if response.get("status") == "success":
                # print(f"[DEBUG] Saving data to DB for query: {query}")
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            #     print(f"[DEBUG] Data saved successfully for query: {query}")
            # else:
            #     print(f"[DEBUG] phone_info returned non-success status for query: {query}")
                
        except Exception as e:
            # print(f"[DEBUG] Exception in save_data for query {query}: {e}")
            log_exception(e)
        # finally:
        #     print(f"[DEBUG] save_data finished for query: {query}")


class check_ssl_cert_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(SSLInfo, 'id', check_ssl_cert, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class wayback_lookup_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(DomainWayback, 'id', wayback_lookup, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class username_check_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(UsernameSearch, 'id', username_check, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class whois_lookup_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(WhoIS, 'id', whois_lookup, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

class nrich_async(AsyncDataProcessing):
    def __init__(self):
        super().__init__(Nrich, 'id', get_nrich_data, 600)
    
    def save_data(self, query, additional_data):
        try:
            response = self.fun(query)
            if response.get("status") == "success":
                report = self.model(id=query, json_data=response.get('data'))
                report.save()
            
        except Exception as e:
            log_exception(e)

nrich = nrich_async()
whois = whois_lookup_async()
username_async = username_check_async()
ip_inf = ip_info_async()
wayback = wayback_lookup_async()

check_ssl = check_ssl_cert_async()
phone_num_info = phone_info_async()

deep_account = deep_account_search_async()

class NrichAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            query = request.query_params.get('query')
            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            max_wait = 30  # seconds
            start_time = time.time()

            while True:
                data = nrich.handle(query=query)  # retry NRICH each loop
                if data.get('data'):
                    # Data is ready → check freshness
                    if data.get("status") == "completed":
                        if check_data_freshness(data.get('data', {})):
                            return Response(data, status=status.HTTP_200_OK)
                        else:
                            Nrich.objects.filter(id=query).delete()
                            data = nrich.handle(query=query)
                            return Response(data, status=status.HTTP_202_ACCEPTED)
                    elif data.get("status", "error") == "processing":
                        return Response(data, status=status.HTTP_202_ACCEPTED)
                    else:
                        return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # Check elapsed time
                elapsed = time.time() - start_time
                if elapsed >= max_wait:
                    return Response(
                        {"status": "error", "message": "Data not found, try again later."},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Wait a short time before retrying
                time.sleep(2)  # retry every 2 seconds

        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeepAccountSearchAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            query = request.query_params.get('query')

            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            data = deep_account.handle(query=query)

            if data.get("status") == "completed":
                if check_data_freshness(data.get('data', {})):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    DeepAccountSearch.objects.filter(id=query).delete()
                    data = deep_account.handle(query=query)
                    return Response(data, status=status.HTTP_202_ACCEPTED)
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SSLInfoAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            query = request.query_params.get('query') # domain address

            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            data = check_ssl.handle(query=query)

            if data.get("status") == "completed":
                if check_data_freshness(data.get('data', {})):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    SSLInfo.objects.filter(id=query).delete()
                    data = check_ssl.handle(query=query)
                    return Response(data, status=status.HTTP_202_ACCEPTED)
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class PhoneInfoAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            query = request.query_params.get('query')
            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            # Clean the query: remove <, >, spaces, etc.
            query = clean_phone_number(query)
            # print(f"[DEBUG] Cleaned query: {query}")

            # Try to fetch existing DB record
            db_record = PhoneNumberInfo.objects.filter(id=query).first()

            if db_record and check_data_freshness(db_record):
                # If data is fresh, serialize and return it
                serializer = PhoneNumberInfoSerializer(db_record)
                return Response({
                    "message": "Data processing successful",
                    "status": "completed",
                    "data": serializer.data
                }, status=200)
            else:
                # If no record or stale, delete old record if exists
                if db_record:
                    db_record.delete()

                # Trigger async fetch
                data = phone_num_info.handle(query=query)

                # If completed, serialize the new record
                if data.get("status") == "completed":
                    new_record = PhoneNumberInfo.objects.filter(id=query).first()
                    if new_record:
                        serializer = PhoneNumberInfoSerializer(new_record)
                        data["data"] = serializer.data

                # Return status based on async thread
                return Response(data, status=202 if data.get("status") == "processing" else 200)

        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=500)



class WaybackAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            query = request.query_params.get('query') # domain

            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            data = wayback.handle(query=query)

            if data.get("status") == "completed":
                if check_data_freshness(data.get('data', {})):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    DomainWayback.objects.filter(id=query).delete()
                    data = wayback.handle(query=query)
                    return Response(data, status=status.HTTP_202_ACCEPTED)
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IPInfoAPI(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            query = request.query_params.get('query') # ip address

            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            data = ip_inf.handle(query=query)

            if data.get("status") == "completed":
                if check_data_freshness(data.get('data', {})):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    IPInfo.objects.filter(id=query).delete()
                    data = ip_info.handle(query=query)
                    return Response(data, status=status.HTTP_202_ACCEPTED)
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WhoIsAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            query = request.query_params.get('query') # domain

            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            data = whois.handle(query=query)


            if data.get("status") == "completed":
                if check_data_freshness(data.get('data', {})):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    WhoIS.objects.filter(id=query).delete()
                    data = whois.handle(query=query)
                    return Response(data, status=status.HTTP_202_ACCEPTED)
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserNameCheck(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            query = request.query_params.get('query')

            if not query:
                return Response({"error": "Missing 'query' parameter"}, status=400)

            data = username_async.handle(query=query)

            if data.get("status") == "completed":
                if check_data_freshness(data.get('data', {})):
                    return Response(data , status=status.HTTP_200_OK)
                else:
                    UsernameSearch.objects.filter(id=query).delete()
                    data = username_async.handle(query=query)
                    return Response(data, status=status.HTTP_202_ACCEPTED)
            elif data.get("status", 'error') == "processing":
                return Response(data, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

