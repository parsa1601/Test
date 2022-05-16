from django.urls import path
from . import views
from .views import ServerAPIView, Check_Notif

urlpatterns = [
    path('server/',ServerAPIView.as_view()),
    path('check/',Check_Notif.as_view())
]
