from django.core.management.base import BaseCommand
from detection.models import MLModelMetadata
import os
from django.conf import settings
import joblib

class Command(BaseCommand):
    help = 'Registers trained models from the models directory into the database'

    def handle(self, *args, **options):
        models_dir = os.path.join(settings.BASE_DIR, 'models')
        
        if not os.path.exists(models_dir):
            self.stdout.write(self.style.ERROR(f'Models directory not found: {models_dir}'))
            return

        # List of known models based on user files
        known_models = ['DecisionTree', 'RandomForest', 'GradientBoosting', 'KNN', 'LogisticRegression', 'SVM']

        for model_name in known_models:
            model_path = os.path.join(models_dir, f"{model_name}_model.pkl")
            
            if os.path.exists(model_path):
                # Check if already exists
                if MLModelMetadata.objects.filter(model_name=model_name).exists():
                    self.stdout.write(self.style.WARNING(f'Model {model_name} already registered.'))
                    continue

                # Create entry
                MLModelMetadata.objects.create(
                    model_name=model_name,
                    version='1.0',
                    accuracy=0.99, # Placeholder, ideally load from metadata if available
                    file_path=model_path,
                    active=(model_name == 'DecisionTree') # Set DecisionTree as active by default
                )
                self.stdout.write(self.style.SUCCESS(f'Successfully registered {model_name}'))
            else:
                self.stdout.write(self.style.WARNING(f'Model file not found for {model_name}'))
