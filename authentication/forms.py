from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class UserRegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'role']
        widgets = {
            'role': forms.Select(choices=User.ROLE_CHOICES)
        }
