
from django.urls import path
from cryptoblock.views import *

urlpatterns = [
    
    path("wallet/", WalletDetails.as_view(), name="wallet"),
    path("wallet_chain_info/", WalletChainDetails.as_view(), name="wallet-chain"),
    path("wallet_history/", WalletHistory.as_view(), name="wallet-history"),
    path("nftswallet_history/", nftsWalletHistory.as_view(), name="nftswallet-history"),
    path("blockchain_details/", BlockchainDetails.as_view(), name="blockchain_details"),
    path("upload_file/", virusTotalFileUpload.as_view(), name="upload-file"),
    path("file_upload_history/", FileUploadHistoryView.as_view(), name="virusTotal_file"),

]