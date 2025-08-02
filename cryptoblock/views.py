from django.shortcuts import render

# Create your views here.
from dotenv import load_dotenv

load_dotenv()

import threading

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from BluHawk.utils import *
from BluHawk import load_env as myenv

from django.http import JsonResponse
from moralis import evm_api
import requests

import rest_framework.exceptions as http_exceptions
from rest_framework.permissions import IsAuthenticated
import sys
import json
import urllib.parse

from cryptoblock.models import FileUploadHistory as uploadhistory


class WalletDetails(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        try:
            address = request.query_params.get("address")

            if not address:
                return Response({"error": "Address is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            wallet_data = {
                "address": address,
            }

            try:
                
                net_worth = evm_api.wallets.get_wallet_net_worth(
                    api_key=myenv.MORALIS,
                    params={
                        "exclude_spam": True,
                        "exclude_unverified_contracts": True,
                        "max_token_inactivity": 1,
                        "min_pair_side_liquidity_usd": 1000,
                        "address": address
                    },
                )

                wallet_data['net_worth'] = net_worth
            except Exception as e:
                pass

            try:
                params = {
                "address": address
                }

                active_chains = evm_api.wallets.get_wallet_active_chains(
                    api_key=myenv.MORALIS,
                    params=params,
                )
                wallet_data['active_chains'] = active_chains
            except Exception as e:
                pass


            try:
                url = f"https://deep-index.moralis.io/api/v2.2/resolve/{address}/domain"
                headers = {
                    "Accept": "application/json",
                    "X-API-Key": myenv.MORALIS
                }
                unstoppable_domain = requests.request("GET", url, headers=headers)
                if unstoppable_domain.status_code == 200:
                    wallet_data['unstoppable_domain'] = unstoppable_domain.json()
            except Exception as e:
                pass

            
            try:
                params = {
                "address": address
                }

                ens_domain = evm_api.resolve.resolve_address(
                    api_key=myenv.MORALIS,
                    params=params,
                )
                wallet_data['ens_domain'] = ens_domain
            except Exception as e:
                pass

            return Response({
                "message":"successful",
                "data":wallet_data
            }, status=status.HTTP_200_OK)
        
        except http_exceptions.NotFound as e:
            return Response({
                "message": "Invalid address or try again later!",
                "data":[]
            }, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            log_exception(e)
            return Response({
                "message": "Invalid address or try again later!",
                "data":[]
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class WalletChainDetails(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        try:
            address = request.query_params.get("address")
            chain = request.query_params.get("chain", "eth")

            if not address:
                return Response({"error": "Address is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            wallet_data = {
                "address": address
            }

            try:

                wallet_stats = evm_api.wallets.get_wallet_stats(
                    api_key=myenv.MORALIS,
                    params= {
                        "chain": chain,
                        "address": address,
                    },
                )
                wallet_data['wallet_stats'] = wallet_stats

            except Exception as e:
                wallet_data['wallet_stats'] = {}
            
            try:
            
                profitability_summary = evm_api.wallets.get_wallet_profitability_summary(
                    api_key=myenv.MORALIS,
                    params={
                        "chain": chain,
                        "address": address,
                    }
                )
                wallet_data['profitability_summary'] = profitability_summary

            except Exception as e:
                wallet_data['profitability_summary'] = {}

            try:
                # list
                wallet_history = evm_api.wallets.get_wallet_history(
                    api_key=myenv.MORALIS,
                    params = {
                        "chain": chain,
                        "order": "DESC",
                        "address": address,
                        "limit":10,
                    },
                )
                wallet_data['wallet_history'] = wallet_history
            except Exception as e:
                wallet_data['wallet_history'] = {}

            try:
                #list
                nfts = evm_api.nft.get_wallet_nfts(
                    api_key=myenv.MORALIS,
                    params={
                        "chain": "eth",
                        "format": "decimal",
                        "media_items": False,
                        "include_prices": True,
                        "normalize_metadata": True,
                        "address": address,
                        'limit': 10,
                    },
                )
                wallet_data['nfts'] = nfts
            except Exception as e:
                wallet_data['nfts'] = {}

            try:
                # list
                nft_trades = evm_api.nft.get_nft_trades_by_wallet(
                    api_key=myenv.MORALIS,
                    params={
                        "chain": chain,
                        "nft_metadata": True,
                        "address": address,
                        "limit":10,
                    },
                )
                wallet_data['nft_trades'] = nft_trades
            except Exception as e:
                wallet_data['nft_trades'] = {}

            return Response({
                "message": "success",
                "data": wallet_data
            }, status=status.HTTP_200_OK)
        
        except http_exceptions.NotFound as e:
            return Response(
                {
                    "message":"Invalid query data or try again!",
                    "data":[]
                }, status= status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            log_exception(e)
            return Response(
                {
                    "message":"Invalid query data or try again!",
                    "data":[]
                }, status= status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#not integrated
class BlockchainDetails(APIView):
    #permission_classes=[IsAuthenticated]
    def get(self, request, *args, **kwargs):
        try:
            hash = request.query_params.get("hash")
            chain = request.query_params.get("chain", 'eth')
            
            if not hash:
                return Response({"error":"Hash is required"},status.HTTP_400_BAD_REQUEST)
            
            params={
                "chain": chain,
                "block_number_or_hash": hash
            }

            blockchain = evm_api.block.get_block(
                api_key=myenv.MORALIS,
                params=params,
            )

            block_data = {
                "blockdata": blockchain
            }

            return Response(block_data, status=status.HTTP_200_OK)

        except Exception as e:
            return log_exception(e)

class WalletHistory(APIView):
    def get(self, request, *args, **kwargs):
        try:
            address = request.query_params.get("address")
            chain = request.query_params.get("chain", 'eth')
            cursor = request.query_params.get("cursor", '')
            page_size = int(request.query_params.get("page_size", 10))

            if not hash:
                    return Response({"error":"Hash is required"},status.HTTP_400_BAD_REQUEST)

            params={
                    "chain": chain,
                    "order": "DESC",
                    "limit": page_size,
                    "address": address
            }

            if cursor:
                params['cursor'] = cursor

            history = evm_api.wallets.get_wallet_history(
                api_key=myenv.MORALIS,
                params=params,
            )
            return Response({
                "message": "success",
                "data": history
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return log_exception(e)

# not integrated
class BlockTransactionsByHash(APIView):
    permission_classes=[IsAuthenticated]
    def get(self, request,*args,**Kwargs):
        try:
            hash = request.query_params.get("hash")
            chain= request.query_params.get("chain","eth")
            if not hash:
                return Response({"error":"Hash is required"},status.HTTP_400_BAD_REQUEST)
            params={
                "transaction_hash":hash,
                "chain":chain
            }
            byhash = evm_api.transaction.get_transaction(
                api_key=myenv.MORALIS,
                params=params,
            )
            hash_data={
                "hashdata": byhash
            }
            return Response(hash_data, status=status.HTTP_200_OK)
        except Exception as e:
            return log_exception(e)
        
class BlockTransactionsByWallet(APIView):
    permission_classes=[IsAuthenticated]
    def get(self, request,*args,**kwargs):
        try:
            address=request.query_params.get("address")
            chain=request.query_params.get("chain","eth")
            cursor=request.query_params.get("cursor","")
            page_size = request.query_params.get("page_size", 10)

            if not address:
                return Response({"error":"Address is required"},status.HTTP_400_BAD_REQUEST)
            params={
                "address":address,
                "chain":chain,                
                "limit":page_size,
                "order":"DESC"
            }
            if cursor:
                params['cursor']=cursor
            byWallet=evm_api.transaction.get_wallet_transactions(
                api_key=myenv.MORALIS,
                params=params,
            )
            walletdata={
                "walletdata": byWallet
            }
            return Response(walletdata,status=status.HTTP_200_OK)
        except Exception as e:
            return log_exception(e)
        

class nftsWalletHistory(APIView):
    #permission_classes=[IsAuthenticated]
    def get(self,request,*args,**kwargs):
        try:
            address = request.query_params.get("address")
            chain = request.query_params.get("chain", 'eth')
            cursor = request.query_params.get("cursor", '')
            page_size = int(request.query_params.get("page_size", 10))

            if not address:
                return Response({"error":"Address is required"},status.HTTP_400_BAD_REQUEST)
            params={
                    "chain": chain,
                    "order": "DESC",
                    "limit": page_size,
                    "address": address
            }
            if cursor:
                params['cursor']=cursor
            nftshistory = evm_api.nft.get_wallet_nfts(
                api_key=myenv.MORALIS,
                params=params,
            )
            return Response({
                "message": "success",
                "data": nftshistory
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return log_exception(e)
        
# not integrated
class nftsTradeWalletHistory(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request,*args,**kwargs):
        try:
            address = request.query_params.get("address")
            chain = request.query_params.get("chain", 'eth')
            cursor = request.query_params.get("cursor", '')
            page_size = int(request.query_params.get("page_size", 10))

            if not address:
                return Response({"error":"Address is required"},status.HTTP_400_BAD_REQUEST)
            params={
                    "chain": chain,
                    "order": "DESC",
                    "limit": page_size,
                    "address": address
            }
            if cursor:
                params['cursor']=cursor
            nftstradehistory = evm_api.nft.get_nft_trades_by_wallet(
                api_key=myenv.MORALIS,
                params=params,
            )
            return Response({
                "message": "success",
                "data": nftstradehistory
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return log_exception(e)

class virusTotalFileUpload(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request,*args,**kwargs):
        
        try:

            user = request.user

            filesuploaded=request.FILES.get("file")
            if not filesuploaded:
                return Response({"error":"File is required"},status.HTTP_400_BAD_REQUEST)
            files= {
                'file':(filesuploaded.name, filesuploaded.file, filesuploaded.content_type)
            }

            api_key=myenv.VIRUS_TOTAL
            url="https://www.virustotal.com/api/v3/files"
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            response = requests.post(url, files=files, headers=headers)
                       
            data=response.json()
            
            ID=data['data']['id'] 
            encoded_id = urllib.parse.quote(ID) 
            
            api_key=myenv.VIRUS_TOTAL
            url="https://www.virustotal.com/api/v3/analyses"
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            
            response = requests.get(url+"/"+encoded_id, headers=headers)

            uploadhistory.objects.create(
                user = user,
                filename = filesuploaded.name,
                filehash = encoded_id,
                json_data = response.json()
            )

            if response.status_code==200:
                return Response({
                        "message": "success",
                        "data": response.json()
                }, status=status.HTTP_200_OK)

            return Response(
                {
                    "status":"failure",
                    "message": "we ran through an error, please try again!",
                    "data":[],
                }
            )
        except Exception as e:
            return log_exception(e)
        

from django.core.paginator import Paginator

class FileUploadHistoryView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        try:
            page_number = request.query_params.get('page', 1)
            page_size = request.query_params.get('page_size', 10)
            
            uploads = uploadhistory.objects.filter(
                user=request.user
            ).order_by('-created_at')
            
            paginator = Paginator(uploads, page_size)
            page_obj = paginator.get_page(page_number)
            
            results = [{
                'filehash': item.filehash,
                'filename': item.filename,
                'json_data': item.json_data,
                'created_at': item.created_at
            } for item in page_obj]
            
            return Response({
                'count': paginator.count,
                'next': page_obj.next_page_number() if page_obj.has_next() else None,
                'previous': page_obj.previous_page_number() if page_obj.has_previous() else None,
                'results': results
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)