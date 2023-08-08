from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name='index'),
    path('profile/', views.profile, name='profile'),
    path('register/', views.account_register, name='register'),
    path('login/', views.account_login, name='login'),
    path('forgot-password/', views.forgot_password, name='forgot-password'),
    path('reset-password/', views.password_reset, name='reset-password'),
    path('logout/', views.account_logout, name='logout'),
]