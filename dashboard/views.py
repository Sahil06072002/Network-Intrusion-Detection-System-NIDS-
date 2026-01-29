import json
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum
from detection.models import DetectionResult, UploadedTrafficFile, MLModelMetadata
from alerts.models import AlertLog
from django.utils import timezone
from datetime import timedelta

@login_required
def dashboard_home(request):
    # Summary Stats - Command Center shows global system telemetry (SRS 6.3)
    results_qs = DetectionResult.objects.all()
    total_files = UploadedTrafficFile.objects.all().count()
    
    total_packets = results_qs.count()
    total_attacks = results_qs.filter(is_malicious=True).count()
    
    # Calculate Percentages
    if total_packets > 0:
        malicious_percent = round((total_attacks / total_packets) * 100, 1)
        normal_percent = round(100 - malicious_percent, 1)
    else:
        malicious_percent = 0
        normal_percent = 0

    is_privileged = request.user.role in ['admin', 'analyst']
    
    if is_privileged:
        total_alerts = AlertLog.objects.count()
        recent_alerts = AlertLog.objects.all().order_by('-timestamp')[:10]
        system_info = {'cpu': 12, 'memory': 45, 'status': 'Healthy'}
    else:
        total_alerts = AlertLog.objects.count() # System-wide count
        recent_alerts = []
        system_info = None

    # Model Status
    active_model = MLModelMetadata.objects.filter(active=True).first()

    # Attack Distribution (Pie Chart)
    attack_distribution = results_qs.filter(is_malicious=True)\
        .values('prediction')\
        .annotate(count=Count('prediction'))\
        .order_by('-count')
    
    attack_labels = [item['prediction'] for item in attack_distribution]
    attack_data = [item['count'] for item in attack_distribution]

    # Recent Activity (Last 7 days)
    last_7_days = timezone.now() - timedelta(days=7)
    daily_activity = results_qs.filter(timestamp__gte=last_7_days)\
        .values('timestamp__date')\
        .annotate(count=Count('id'))\
        .order_by('timestamp__date')
    
    trend_labels = [str(item['timestamp__date']) for item in daily_activity]
    trend_data = [item['count'] for item in daily_activity]

    # Daily Attack Mix
    daily_mix_raw = results_qs.filter(is_malicious=True, timestamp__gte=last_7_days)\
        .values('timestamp__date', 'prediction')\
        .annotate(count=Count('id'))\
        .order_by('timestamp__date')
    
    daily_mix_data = {}
    for label in attack_labels:
        daily_mix_data[label] = [0] * len(trend_labels)
    
    day_to_idx = {day: i for i, day in enumerate(trend_labels)}
    for item in daily_mix_raw:
        day_str = str(item['timestamp__date'])
        if day_str in day_to_idx:
            idx = day_to_idx[day_str]
            label = item['prediction']
            if label in daily_mix_data:
                daily_mix_data[label][idx] = item['count']

    # Model breakdown for admins
    model_performance = []
    if is_privileged:
        model_performance = list(results_qs.filter(is_malicious=True)\
            .values('model_used')\
            .annotate(count=Count('model_used'))\
            .order_by('-count'))

    context = {
        'total_files': total_files,
        'total_packets': total_packets,
        'total_attacks': total_attacks,
        'malicious_percent': malicious_percent,
        'normal_percent': normal_percent,
        'total_alerts': total_alerts,
        'system_health': system_info,
        'active_model': active_model,
        'attack_labels_json': json.dumps(attack_labels),
        'attack_data_json': json.dumps(attack_data),
        'trend_labels_json': json.dumps(trend_labels),
        'trend_data_json': json.dumps(trend_data),
        'daily_mix_data': daily_mix_data, 
        'recent_alerts': recent_alerts,
        'model_performance': model_performance,
        'is_privileged': is_privileged
    }
    return render(request, 'dashboard/command_center.html', context)
