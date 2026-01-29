from django.contrib.auth.decorators import user_passes_test

def admin_required(function=None):
    actual_decorator = user_passes_test(
        lambda u: u.is_active and (u.is_superuser or u.role == 'admin'),
        login_url='login',
        redirect_field_name=None
    )
    if function:
        return actual_decorator(function)
    return actual_decorator

def analyst_required(function=None):
    actual_decorator = user_passes_test(
        lambda u: u.is_active and (u.is_superuser or u.role in ['admin', 'analyst']),
        login_url='login',
        redirect_field_name=None
    )
    if function:
        return actual_decorator(function)
    return actual_decorator
