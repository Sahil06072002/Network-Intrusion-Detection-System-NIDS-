from django.core.management.base import BaseCommand
from scapy.all import sniff
from ml_engine.feature_extractor import FlowAggregator
from ml_engine.predictor import NIDSPredictor
from detection.models import DetectionResult
from alerts.models import AlertLog
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import time
import threading

class Command(BaseCommand):
    help = 'Starts the real-time packet sniffer'

    def handle(self, *args, **options):
        import os, sys
        self.stdout.write(f"Expert NIDS: sys.path[0] = {sys.path[0]}")
        models_root = r"D:\CDAC\project\new_v2\network-ids-all_models"
        self.stdout.write(f"Expert NIDS: Models root exists? {os.path.exists(models_root)}")
        
        self.stdout.write(self.style.SUCCESS('Expert NIDS: Initializing Real-Time Sniffer...'))
        
        self.aggregator = FlowAggregator(timeout=10.0) # Increased timeout for more flow data
        self.predictor = NIDSPredictor() # Multi-model lead
        
        self.running = True
        timeout_thread = threading.Thread(target=self.check_timeouts_loop)
        timeout_thread.daemon = True
        timeout_thread.start()

        self.stdout.write(self.style.SUCCESS('Expert NIDS: Sniffing active on default interface. Press Ctrl+C to terminate.'))
        try:
            # Expert Tip: store=0 is critical for high-throughput live monitoring
            sniff(prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            self.running = False
            self.stdout.write(self.style.SUCCESS('\nExpert NIDS: Termination signal received. Stopping...'))

    def process_packet(self, packet):
        self.aggregator.process_packet(packet)

    def check_timeouts_loop(self):
        while self.running:
            time.sleep(2.0)
            finished_flows = self.aggregator.get_finished_flows()
            if finished_flows:
                self.analyze_flows(finished_flows)
            
            self.aggregator.check_timeouts(time.time())

    def analyze_flows(self, flows):
        df = self.aggregator.to_dataframe(flows)
        if df.empty:
            return

        # Multi-model prediction (Expert logic)
        predictions = self.predictor.predict(df)
        
        results_to_create = []
        alerts_to_create = []

        for i, (label, conf, model_used) in enumerate(predictions):
            flow = flows[i]
            is_malicious = (label != 'BENIGN')
            
            # Persist to Security Command Center
            results_to_create.append(DetectionResult(
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                protocol=f"{flow.proto}/{flow.dst_port}",
                prediction=label,
                confidence=conf,
                is_malicious=is_malicious,
                model_used=model_used
            ))

            if is_malicious:
                severity = 'high' if conf > 0.8 else 'info'
                alerts_to_create.append(AlertLog(
                    severity=severity,
                    message=f"Expert Alert: {label} detected via agent {model_used}",
                    source_ip=flow.src_ip,
                    attack_type=label
                ))
                self.stdout.write(self.style.WARNING(f" [THREAT] {label} identified by {model_used} | Score: {conf:.2f}"))
                
                # SRS 7.5: Dispatch email for critical/high threats
                if severity == 'high':
                    try:
                        send_mail(
                            subject=f"⚠️ NIDS CRITICAL ALERT: {label}",
                            message=f"Expert System detected a HIGH severity threat.\n\nType: {label}\nSource: {flow.src_ip}\nAgent: {model_used}\nTime: {timezone.now()}",
                            from_email=None,
                            recipient_list=['security-team@nids.expert'],
                            fail_silently=True
                        )
                    except:
                        pass

        # Expert-level bulk persistence
        if results_to_create:
            DetectionResult.objects.bulk_create(results_to_create)
        if alerts_to_create:
            AlertLog.objects.bulk_create(alerts_to_create)
