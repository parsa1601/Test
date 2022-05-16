from rest_framework import serializers
from .models import Notif


class NotifSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=100)
    number = serializers.IntegerField()
    
    
    

    def create(self, validated_data):
        return Notif.objects.create(**validated_data)


    def update(self, instance, validated_data):
        instance.message = validated_data.get('message', instance.message) 
        instance.number = validated_data.get('number', instance.published_date)

        
        return instance


# from rest_framework import serializers
# from .models import Article


# class ArticleSerializer(serializers.Serializer):
#     class meta:
#             model = Article
#             # fields = ['id' , 'title' , 'author' , 'date']
#             fields = '__all__'