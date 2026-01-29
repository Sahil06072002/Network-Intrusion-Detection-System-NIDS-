from django.contrib import admin
from .models import UploadedTrafficFile, DetectionResult, MLModelMetadata

@admin.register(UploadedTrafficFile)
class UploadedTrafficFileAdmin(admin.ModelAdmin):
    list_display = ('id', 'file', 'uploaded_by', 'uploaded_at', 'processed')
    list_filter = ('processed', 'uploaded_at')
    search_fields = ('description', 'file')
    readonly_fields = ('uploaded_at',)

@admin.register(DetectionResult)
class DetectionResultAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'destination_ip', 'protocol', 'prediction', 'confidence', 'is_malicious')
    list_filter = ('is_malicious', 'prediction', 'protocol', 'timestamp')
    search_fields = ('source_ip', 'destination_ip')
    ordering = ('-timestamp',)

@admin.register(MLModelMetadata)
class MLModelMetadataAdmin(admin.ModelAdmin):
    list_display = ('model_name', 'version', 'accuracy', 'created_at', 'active')
    list_filter = ('active', 'model_name')
    list_editable = ('active',)
    actions = ['retrain_model_action']

    def retrain_model_action(self, request, queryset):
        from ml_engine.trainer import retrain_model
        # Use a sample dataset path for demonstration if none provided
        sample_csv = r"D:\CDAC\project\new_v2\all_traffic.csv"
        
        for model_meta in queryset:
            success, result = retrain_model(model_meta.model_name, sample_csv)
            if success:
                model_meta.accuracy = result['accuracy']
                model_meta.version = f"v{float(model_meta.version[1:]) + 0.1:.1f}"
                model_meta.save()
                self.message_user(request, f"Expert System: {model_meta.model_name} retrained successfully. New Acc: {result['accuracy']}%")
            else:
                self.message_user(request, f"Error retraining {model_meta.model_name}: {result}", level='error')
    
    retrain_model_action.short_description = "Retrain selected models using all_traffic.csv"
