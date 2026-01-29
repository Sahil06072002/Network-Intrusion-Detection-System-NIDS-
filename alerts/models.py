from django.db import models

class AlertLog(models.Model):
    SEVERITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    message = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    attack_type = models.CharField(max_length=50, null=True, blank=True)
    is_resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"[{self.severity}] {self.message} ({self.timestamp})"
