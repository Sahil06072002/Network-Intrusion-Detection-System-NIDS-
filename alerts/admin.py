from django.contrib import admin
from .models import AlertLog

@admin.register(AlertLog)
class AlertLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'severity', 'attack_type', 'source_ip', 'is_resolved')
    list_filter = ('severity', 'is_resolved', 'attack_type')
    search_fields = ('message', 'source_ip')
    ordering = ('-timestamp',)
    actions = ['mark_as_resolved']

    @admin.action(description='Mark selected alerts as resolved')
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(is_resolved=True)
        self.message_user(request, f'{updated} alerts were successfully marked as resolved.')
