from django.apps import AppConfig


class HumantextConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'humantext'
    def ready(self):
        import humantext.signals 