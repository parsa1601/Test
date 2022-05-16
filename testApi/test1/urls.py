from django.urls import path
from .views import ArticleAPIView, ArticleDetailsAPIView
from . import views

urlpatterns = [
    path('server/',ServerAPIView.as_view())
]
