from django import forms
from .models import UploadedTrafficFile

class TrafficUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedTrafficFile
        fields = ['file', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }
