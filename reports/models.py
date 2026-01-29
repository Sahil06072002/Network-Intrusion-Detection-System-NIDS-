from django.db import models
from django.conf import settings

class Report(models.Model):
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file_path = models.FileField(upload_to='reports/')
    report_type = models.CharField(max_length=50, default='General')

    def __str__(self):
        return f"Report {self.id} - {self.generated_at}"
