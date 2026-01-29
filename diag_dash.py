import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nids_backend.settings')
django.setup()

from detection.models import DetectionResult
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count

def diagnostic():
    last_7 = timezone.now() - timedelta(days=7)
    results_qs = DetectionResult.objects.all()
    
    # Modern way
    daily = results_qs.filter(timestamp__gte=last_7)\
        .values('timestamp__date')\
        .annotate(count=Count('id'))\
        .order_by('timestamp__date')
    
    # Legacy way (checking if it returns anything)
    daily_extra = results_qs.filter(timestamp__gte=last_7)\
        .extra(select={'day': 'date(timestamp)'})\
        .values('day')\
        .annotate(count=Count('id'))\
        .order_by('day')
        
    print(f"Total results: {results_qs.count()}")
    print(f"Modern daily counts: {list(daily)}")
    print(f"Extra daily counts: {list(daily_extra)}")
    
    import json
    attack_labels = [item['prediction'] for item in results_qs.filter(is_malicious=True).values('prediction').annotate(c=Count('id'))]
    print(f"Attack Labels JSON: {json.dumps(attack_labels)}")
    print(f"Trend Labels JSON: {json.dumps([str(item['timestamp__date']) for item in daily])}")

if __name__ == "__main__":
    diagnostic()
