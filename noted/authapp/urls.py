from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.signup, name='register'),
    path('login/', views.login, name='login'),
    path('test/', views.test_token, name='test_token'),  # Don't forget the trailing slash
]
