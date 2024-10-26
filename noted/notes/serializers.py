from . models import notes
from rest_framework import serializers

class Notesserializers(serializers.ModelSerializer):
    class Meta(object):
        model = notes
        fields = ['id','email','title','content','created_at','updated_at']
