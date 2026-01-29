from django.urls import path
from . import views

urlpatterns = [
    path('download/<int:pk>/', views.download_report, name='download_report'),
]
