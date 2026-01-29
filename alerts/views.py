from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import AlertLog
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.contrib import messages
from authentication.decorators import analyst_required

@login_required
def alert_list(request):
    severity_filter = request.GET.get('severity')
    
    alerts = AlertLog.objects.all().order_by('-timestamp')
    
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
        
    paginator = Paginator(alerts, 20) # Show 20 alerts per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'alerts/alert_list.html', {
        'page_obj': page_obj,
        'severity_filter': severity_filter
    })

@login_required
def alert_detail(request, pk):
    alert = get_object_or_404(AlertLog, pk=pk)
    return render(request, 'alerts/alert_detail.html', {'alert': alert})

@login_required
@analyst_required
def resolve_alert(request, pk):
    alert = get_object_or_404(AlertLog, pk=pk)
    alert.is_resolved = True
    alert.save()
    messages.success(request, f'Alert #{alert.id} marked as resolved.')
    return redirect('alert_list')
@login_required
def recent_alerts_api(request):
    """Expert System: Tiny API for dashboard AJAX polling."""
    # Only privileged users see the global live feed
    if request.user.role not in ['admin', 'analyst']:
        return JsonResponse({'alerts': []})
        
    alerts = AlertLog.objects.order_by('-timestamp')[:10]
    data = []
    for a in alerts:
        data.append({
            'timestamp': a.timestamp.strftime('%H:%M:%S'),
            'severity': a.severity,
            'message': a.message,
            'source_ip': a.source_ip,
            'is_resolved': a.is_resolved
        })
    return JsonResponse({'alerts': data})
