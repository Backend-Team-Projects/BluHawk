
from django.urls import path
from .views import VirusTotalGraphSearchView

urlpatterns = [
    
     path("search/", VirusTotalGraphSearchView.as_view(), name="graph-search"),
     # path("filter/", FilterTypeView.as_view(), name="filter-type"),

]   
