from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from .utils import render_to_pdf
from detection.models import UploadedTrafficFile, DetectionResult
from django.db.models import Count

@login_required
def download_report(request, pk):
    traffic_file = get_object_or_404(UploadedTrafficFile, pk=pk, uploaded_by=request.user)
    results = DetectionResult.objects.filter(traffic_file=traffic_file)
    
    # Stats
    total_packets = results.count()
    malicious_packets = results.filter(is_malicious=True)
    total_attacks = malicious_packets.count()
    
    attack_distribution = malicious_packets.values('prediction').annotate(count=Count('prediction')).order_by('-count')
    
    # Get top 50 malicious entries for the report to avoid huge PDFs
    malicious_list = malicious_packets.order_by('timestamp')[:50]

    context = {
        'file': traffic_file,
        'total_packets': total_packets,
        'total_attacks': total_attacks,
        'attack_distribution': attack_distribution,
        'malicious_list': malicious_list,
        'user': request.user,
    }
    
    pdf = render_to_pdf('reports/pdf_template.html', context)
    if pdf:
        response = pdf
        filename = f"NIDS_Report_{traffic_file.id}.pdf"
        content = f"inline; filename='{filename}'"
        response['Content-Disposition'] = content
        return response
    return HttpResponse("Error Rendering PDF", status=400)
