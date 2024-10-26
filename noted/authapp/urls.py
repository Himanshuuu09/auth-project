from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.signup, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout_view, name='test_token'),  # Don't forget the trailing slash
    path('send_otp/',views.send_otp,name="send_otp"),
    path('forget_pwd/',views.forget_pwd, name='forget_pwd'),#?token==
]

