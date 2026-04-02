from django.urls import path
from .views import TriggerSOSView, GetSOSAlertsView, AcknowledgeSOSView, ResolveSOSView

urlpatterns = [
    path('trigger/', TriggerSOSView.as_view(), name='trigger-sos'),
    path('alerts/', GetSOSAlertsView.as_view(), name='sos-alerts'),
    path('acknowledge/<uuid:sos_id>/', AcknowledgeSOSView.as_view(), name='acknowledge-sos'),
    path('resolve/<uuid:sos_id>/', ResolveSOSView.as_view(), name='resolve-sos'),
]