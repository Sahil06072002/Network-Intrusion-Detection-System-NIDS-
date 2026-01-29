from django.urls import path
from . import views

urlpatterns = [
    path('', views.alert_list, name='alert_list'),
    path('<int:pk>/', views.alert_detail, name='alert_detail'),
    path('<int:pk>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('api/recent/', views.recent_alerts_api, name='recent_alerts_api'),
]
