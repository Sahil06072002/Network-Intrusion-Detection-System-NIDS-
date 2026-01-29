from django.db import models
from django.conf import settings

class UploadedTrafficFile(models.Model):
    file = models.FileField(upload_to='traffic_uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    description = models.TextField(blank=True)
    processed = models.BooleanField(default=False)

    def __str__(self):
        return f"File {self.id} - {self.uploaded_at}"

class MLModelMetadata(models.Model):
    model_name = models.CharField(max_length=100)
    version = models.CharField(max_length=20)
    accuracy = models.FloatField()
    file_path = models.CharField(max_length=255) # Path to .pkl file
    created_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.model_name} v{self.version}"

class DetectionResult(models.Model):
    traffic_file = models.ForeignKey(UploadedTrafficFile, on_delete=models.CASCADE, null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    protocol = models.CharField(max_length=20, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    prediction = models.CharField(max_length=50) # e.g., 'Normal', 'DoS'
    confidence = models.FloatField()
    is_malicious = models.BooleanField(default=False)
    model_used = models.CharField(max_length=100, null=True, blank=True) # New field to track the detecting model

    def __str__(self):
        return f"{self.prediction} ({self.model_used}) - {self.timestamp}"
