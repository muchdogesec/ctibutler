"""
URL configuration for ctibutler project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework import routers
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from ctibutler.server import views
import dogesec_commons.objects.views as arango_views


from django.http import JsonResponse

def handler404(*args, **kwargs):
    return JsonResponse(dict(code=404, message='non-existent page'), status=404)

def handler500(*args, **kwargs):
    return JsonResponse(dict(code=500, message='internal server error'), status=500)

API_VERSION = "v1"

router = routers.SimpleRouter(use_regex_path=False)
router.register("jobs", views.JobView, "jobs-view")
# arango-cti-processor
router.register("arango-cti-processor/<str:mode>", views.ACPView, "acp-view")
# location
router.register("location", views.LocationView, "location-view")

# mitre
## mitre cwe/capec/atlas
router.register("cwe", views.CweView, "cwe-view")
router.register("atlas", views.AtlasView, "atlas-view")
router.register("disarm", views.DisarmView, "disarm-view")
router.register("capec", views.CapecView, "capec-view")
## mitre att&ck
router.register("attack-mobile", views.AttackView.attack_view('mobile'), "attack-mobile-view")
router.register("attack-ics", views.AttackView.attack_view('ics'), "attack-ics-view")
router.register("attack-enterprise", views.AttackView.attack_view('enterprise'), "attack-enterprise-view")
## objects
## objects
obj_router = routers.SimpleRouter(use_regex_path=True)
obj_router.register("", arango_views.SingleObjectView, "object-view-orig")
obj_router.register('smos', arango_views.SMOView, "object-view-smo")
obj_router.register('scos', arango_views.SCOView, "object-view-sco")
obj_router.register('sros', arango_views.SROView, "object-view-sro")
obj_router.register('sdos', arango_views.SDOView, "object-view-sdo")




urlpatterns = [
    path(f'api/healthcheck/', views.health_check),
    path(f'api/{API_VERSION}/', include(router.urls)),
    path(f'api/{API_VERSION}/objects/', include(obj_router.urls)),
    path('admin/', admin.site.urls),
    # YOUR PATTERNS
    path('api/schema/', views.SchemaViewCached.as_view(), name='schema'),
    # Optional UI:
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
