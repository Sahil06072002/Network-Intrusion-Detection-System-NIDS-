from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import UploadedTrafficFile, DetectionResult
from .forms import TrafficUploadForm
from ml_engine.predictor import NIDSPredictor
import pandas as pd
from django.contrib import messages

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = TrafficUploadForm(request.POST, request.FILES)
        if form.is_valid():
            traffic_file = form.save(commit=False)
            traffic_file.uploaded_by = request.user
            traffic_file.save()
            
            # Trigger processing
            try:
                process_traffic_file(traffic_file)
                messages.success(request, 'File uploaded and processed successfully!')
                return redirect('file_list')
            except Exception as e:
                messages.error(request, f'Error processing file: {str(e)}')
                traffic_file.delete() # Cleanup on failure
    else:
        form = TrafficUploadForm()
    return render(request, 'detection/upload.html', {'form': form})

@login_required
def file_list(request):
    files = UploadedTrafficFile.objects.filter(uploaded_by=request.user).order_by('-uploaded_at')
    return render(request, 'detection/file_list.html', {'files': files})

@login_required
def file_detail(request, pk):
    traffic_file = get_object_or_404(UploadedTrafficFile, pk=pk, uploaded_by=request.user)
    results = DetectionResult.objects.filter(traffic_file=traffic_file)
    
    # Simple pagination or limit for performance if needed
    # results = results[:1000] 
    
    return render(request, 'detection/file_detail.html', {'file': traffic_file, 'results': results})

def process_traffic_file(traffic_file):
    # Load CSV
    df = pd.read_csv(traffic_file.file.path)
    
    # Predict using the expert multi-model system
    predictor = NIDSPredictor() 
    predictions = predictor.predict(df)
    
    # Save results
    results_to_create = []
    for index, (label, conf, model_used) in enumerate(predictions):
        # Extract metadata from DF if available
        src_ip = df.iloc[index].get('Source IP', 'N/A')
        dst_ip = df.iloc[index].get('Destination IP', 'N/A')
        proto = df.iloc[index].get('Protocol', 'N/A')
        dst_port = df.iloc[index].get('Destination Port', 0)
        
        results_to_create.append(DetectionResult(
            traffic_file=traffic_file,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=f"{proto}/{dst_port}",
            prediction=label,
            confidence=conf,
            is_malicious=(label != 'BENIGN'),
            model_used=model_used
        ))
    
    # Expert-level bulk processing with batching for high-throughput
    batch_size = 5000
    for i in range(0, len(results_to_create), batch_size):
        DetectionResult.objects.bulk_create(results_to_create[i:i + batch_size])
    
    traffic_file.processed = True
    traffic_file.save()
