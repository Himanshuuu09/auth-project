from django.urls import path
from . import views

urlpatterns = [
    path('create_notes/', views.create_notes, name='create_notes'),
    path('get_notes/', views.get_notes, name='get_notes'),
    path('update_notes/', views.update_notes, name='update_notes'),  # Don't forget the trailing slash
    path('delete_notes/',views.delete_notes,name="delete_notes"),
]

